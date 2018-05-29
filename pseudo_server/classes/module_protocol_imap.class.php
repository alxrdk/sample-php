<?php

interface module_protocol_imap_session {

	const STATE_INIT = 0 ;
	const STATE_LOGIN = 1 ;
	const STATE_LIST = 2 ;
	const STATE_EXAMINE = 3 ;
	const STATE_SEARCH = 4 ;
	const STATE_CHECK = 5 ;
	const STATE_EXPUNGE = 6 ;
	const STATE_BODY = 7 ;
	const STATE_UID = 8 ;
	const STATE_DATA = 9 ;
	const STATE_CMD = 10 ;

 	const MODE_RAW = 1 ;
 	const MODE_BASE64 = 2 ;
}

class module_protocol_imap_parser implements module_protocol_imap_session {

	public $state = NULL ;

	private $stream ;

	public $buffer = NULL ;
	public $buf_offset = 0 ;

	public $content = NULL ;
	public $content_size ;



	public $metadata ;
	public $command ;
	public $cid ;
	public $params ;


	public function __construct() {

		$this->stream = fopen("php://memory", 'r+b') ;
	}

	public function __destruct() {

		fclose($this->stream) ;
		unset($this->stream) ;
	}

	public function release() {

		$this->buffer = null ;
		$this->buf_offset = 0 ;
		$this->__destruct() ;
		$this->__construct() ;

	}

	public function parse_data($data) {

   		$buf = &$this->buffer ;
   		$buf_offset = &$this->buf_offset ;
   		//$buf_offset = strlen($buf) ;
   		$buf.= $data ;

		if ($this->state == self::STATE_DATA) {
   				$content_offset = strlen($this->content) ;
				$this->content.= $data ;
				if (strlen($this->content) >= $this->content_size) {

					$this->content = substr($this->content, 0, $this->content_size) ;
					$buf_offset+= $this->content_size ;
					return true ;
				} else
					return false ;
		}

		if (($ln_pos = strpos($buf, "\n", $buf_offset)) === false)
			return false ;

		$cmd_line = trim(substr($buf, $buf_offset, $ln_pos - $buf_offset)) ;
		$buf_offset+= $ln_pos - $buf_offset + 1 ;

		switch($this->state) {

			case self::STATE_LOGIN:

				if (preg_match('/^([a-zA-Z]\d{3})\sLOGIN\s\S+\s([A-F0-9]{32})/', $cmd_line, $m)) {					$this->cid = $m[1] ;
					$this->metadata = $m[2] ;
					return true ;
				} else
					return false ;

			break ;

			case self::STATE_LIST:

				if (preg_match('/^([a-zA-Z]\d{3})\sLIST\s""\s"\*"/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					return true ;
				} else
					return false ;

			break ;

			case self::STATE_EXAMINE:

				if (preg_match('/^([a-zA-Z]\d{3})\sEXAMINE\sINBOX/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					return true ;
				} else
					return false ;

			break ;

			case self::STATE_CMD:

				if (preg_match('/^([a-zA-Z]\d{3})\s(SEARCH)\sTEXT\s"([A-Za-z0-9\/=]+)"/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					$this->command = $m[2] ;
					$this->params[] = $m[3] ;
					return true ;
				} elseif (preg_match('/^([a-zA-Z]\d{3})\s(CHECK|EXPUNGE)/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					$this->command = $m[2] ;
					return true ;
				} elseif (preg_match('/^([a-zA-Z]\d{3})\s(FETCH)\s(\d+)\sBODY\[(\d+)\]<(\d+)\.(\d+)>/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					$this->command = $m[2] ;
					$this->params = array_slice($m, 3, 4) ;
					return true ;
				} elseif (preg_match('/^([a-zA-Z]\d{3})\s(UID)\sFETCH\s(\d+):(\d+)\sFLAGS/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					$this->command = $m[2] ;
					$this->params = array_slice($m, 3, 2) ;
					return true ;
				} elseif (preg_match('/^([a-zA-Z]\d{3})\s(APPEND)\s(\d)\s\(\\\\Seen\)\s\{(\d+)\}/', $cmd_line, $m)) {
					$this->cid = $m[1] ;
					$this->command = $m[2] ;
					$this->params = array_slice($m, 3, 2) ;
					$this->content = substr($buf, $buf_offset, $m[4]) ;
					return true ;
				} else
					return false ;

			break ;

		}

		return false ;
	}

}

class module_protocol_imap_composter {

	const MSG_WELCOME = "* OK IMAP4rev1 Service Ready" ;
	const MSG_LOGIN = "%s OK LOGIN completed" ;
	const MSG_LIST = "* LIST (\\HasNoChildren) \".\" \"INBOX\"\n%s" ;
	const MSG_LIST_COMPLETED = "%s OK List completed." ;
	const MSG_EXAMINE = "* %d EXISTS\n* OK [UIDVALIDITY %d] UIDs valid\n%s" ;
	const MSG_EXAMINE_COMPLITED = "%s OK [READ-WRITE] SELECT completed" ;
	const MSG_SEARCH = "* SEARCH\n" ;
	const MSG_SEARCH_COMPLITED = "%s OK SEARCH Completed" ;
	const MSG_CHECK = "%s OK CHECK Completed" ;
	const MSG_EXPUNGE = "OK EXPUNGE Completed" ;
	const MSG_BODY = "* 1 FETCH BODY[] %d\n%s\n" ;
	const MSG_BODY_COMPLITED = "%s OK Fetch completed." ;
	const MSG_UID = "%s OK UID FETCH Completed" ;
	const MSG_APPEND = "%s OK APPEND Completed" ;

	public $command_id ;

	public function __construct() {
	}

	public function __destruct() {
	}

	public function msg($msg) {

		return sprintf("%s\n", $msg) ;
	}

	public function error() {

		return sprintf("ERROR\n") ;
	}

	public function init_session() {
		return $this->msg(self::MSG_WELCOME) ;
	}

	public function cmd_login() {
		return $this->msg(sprintf(self::MSG_LOGIN, $this->command_id)) ;
	}

	public function cmd_list() {

		$list = array(
			'SentMail' => '\Sent \HasNoChildren',
			'MyDrafts' => '\Marked \Drafts \HasNoChildren',
			'Trash' => '\Trash \HasNoChildren'
		) ;

		$str = NULL ;
		$count = sizeof($list) ;
		foreach($list as $key=>$val)
			$str.= sprintf("* LIST (%s) \"\/\" %s%s", $val, $key, (++$i < $count)?"\n":NULL) ;

		return $this->msg(sprintf(self::MSG_LIST, $str)).
			   $this->msg(sprintf(self::MSG_LIST_COMPLETED, $this->command_id)) ;
	}

	public function cmd_examine($length) {

		mt_rand() ;
		$num = mt_rand(1, 16) ;
		$recent = mt_rand(1, $num) ;
		$unseen = $num - $recent ;

		$list = array(
			sprintf('%d RECENT', $recent),
			sprintf('OK [UNSEEN %d] Message %d is first unseen', $unseen, $unseen),
			sprintf('OK [UIDNEXT %d] Predicted next UID', mt_rand(128, 65536)),
			'FLAGS (\Answered \Flagged \Deleted \Seen \Draft)',
			'OK [PERMANENTFLAGS ()] No permanent flags permitted'
		) ;

		$str = NULL ;
		$count = sizeof($list) ;
		foreach($list as $val)			$str.= sprintf("* %s%s", $val, (++$i < $count)?"\n":NULL) ;

		return $this->msg(sprintf(self::MSG_EXAMINE, mt_rand(1, 128), $length, $str)).
			   $this->msg(sprintf(self::MSG_EXAMINE_COMPLITED, $this->command_id)) ;
	}

	public function cmd_search() {
		return $this->msg(self::MSG_SEARCH).
			   $this->msg(sprintf(self::MSG_SEARCH_COMPLITED, $this->command_id)) ;
	}

	public function cmd_check() {
		return $this->msg(self::MSG_CHECK) ;
	}

	public function cmd_expunge() {
		return $this->msg(self::MSG_EXPUNGE) ;
	}

	public function cmd_uid() {
		return $this->msg(self::MSG_UID) ;
	}

	public function cmd_write() {
		return $this->msg(self::MSG_APPEND) ;
	}

	public function cmd_read($len, $data) {
		return sprintf(self::MSG_BODY, $len, $data).
			   $this->msg(sprintf(self::MSG_BODY_COMPLITED, $this->command_id)) ;
	}

}

class module_protocol_imap_messager implements module_protocol_imap_session {

	const CMD_HEARTBEAT = 9 ;
	const CMD_READ = 3 ;
	const CMD_READ_COMPLETE = 4 ;
	const CMD_PREPARE = 6 ;
	const CMD_WRITE = 7 ;
	const CMD_WRITE_COMPLETE = 8 ;

	const CMD_PROTO_LOGIN = -1 ;
	const CMD_PROTO_LIST = -10 ;
	const CMD_PROTO_EXAMINE = -2 ;
	const CMD_PROTO_INIT = -6 ;
	const CMD_PROTO_APPEND = -7 ;
	const CMD_PROTO_DATA = -9 ;
	const CMD_PROTO_UID = -8 ;
	const CMD_PROTO_QUIT = -11 ;

	private $metadata = NULL ;
	private $command = NULL ;
	private $offset = NULL ;
	private $len = NULL ;
	private $mode = NULL ;
	public $buffer = NULL ;
	private $data = NULL ;
	private $count = NULL ;

	private function unpack_int($type, $data) {
    	return array_shift(unpack($type, $data)) ;
	}

	private function decode($data, $mode) {
		switch($mode) {
			case self::MODE_RAW:
				return $data ;
			break ;

			case self::MODE_BASE64:
				return base64_decode($data) ;			break ;

		}

    	return false ;
	}

	public function parse(&$parser, &$handler) {
		$this->command_id = $parser->cid ;

		if ($parser->state == NULL) {
			$parser->state = self::STATE_LOGIN ;
			$this->command = self::CMD_PROTO_INIT ;
			return true ;
		}

		if ($parser->state == self::STATE_LOGIN) {
			$metadata = &$parser->metadata ;
			if (!preg_match('/^[0-9A-F]{32}$/', $metadata))
				return false ;

			$this->metadata = $metadata ;

			$this->len = $handler->heartbeat($this->metadata) ;

			$parser->state = self::STATE_LIST ;
			$this->command = self::CMD_PROTO_LOGIN ;
			return true ;
		}

		if ($parser->state == self::STATE_LIST) {
			$parser->state = self::STATE_EXAMINE ;
			$this->command = self::CMD_PROTO_LIST ;
			return true ;
		}

		if ($parser->state == self::STATE_EXAMINE) {
			$parser->state = self::STATE_CMD ;
			$this->command = self::CMD_PROTO_EXAMINE ;
			return true ;
		}

		if ($parser->state == self::STATE_DATA) {

			if (is_null($this->metadata) || is_null($this->offset) || is_null($this->len) || is_null($this->mode))
				return false ;

			if (!$this->data = $this->decode($parser->content, $this->mode))
				return false ;
			$this->data = $handler->write($this->metadata, $this->offset, $this->len, $this->data, $this->mode) ;
			$parser->state = self::STATE_CMD ;
			$this->command = self::CMD_WRITE ;
			return true ;
		}

		if ($parser->state == self::STATE_CMD) {

			$params = $parser->params ;

			switch($parser->command) {

				case 'SEARCH':

					if (!isset($params[0]))
						return false ;

					$size = $this->unpack_int("L", base64_decode($params[0])) ;

					$handler->prepare($this->metadata, $size) ;
					$this->command = self::CMD_PREPARE ;
					return true ;
				break ;

				case 'CHECK':

					$handler->read_complete($this->metadata) ;
					$this->command = self::CMD_READ_COMPLETE ;
					return true ;
				break ;

				case 'EXPUNGE':

					$handler->write_complete($this->metadata) ;
					$this->command = self::CMD_WRITE_COMPLETE ;
					return true ;
				break ;

				case 'FETCH':

					if (!is_array($params))
						return false ;

					list($number, $this->mode, $this->offset, $this->len) = $params ;

					$this->data = $handler->read($this->metadata, $this->offset, $this->len, $this->mode) ;
					$this->len = strlen($this->data) ;
					$this->command = self::CMD_READ ;
					return true ;
				break ;

				case 'UID':

					if (!is_array($params))
						return false ;

					list($this->offset, $this->len) = $params ;

					$this->command = self::CMD_PROTO_DATA ;
					return true ;
				break ;

				case 'APPEND':

					if (!is_array($params))
						return false ;

					list($this->mode, $size) = $params ;

					$parser->content_size = (int)$size ;

					$parser->state = self::STATE_DATA ;
					$this->command = self::CMD_PROTO_APPEND ;
					return true ;
				break ;

			}

		}

		return false ;
	}

	public function compose(&$composter) {

		$composter->command_id = $this->command_id ;

		switch ($this->command) {

			case self::CMD_PROTO_INIT:
				return $composter->init_session() ;
			break ;

			case self::CMD_PROTO_LOGIN:
				return $composter->cmd_login() ;
			break ;

			case self::CMD_PROTO_LIST:
				return $composter->cmd_list() ;
			break ;

			case self::CMD_PROTO_EXAMINE:
				return $composter->cmd_examine($this->len) ;
			break ;

			case self::CMD_HEARTBEAT:
				return $composter->cmd_auth($this->len) ;
			break ;

			case self::CMD_PROTO_DATA:
				return $composter->cmd_uid() ;
			break ;

			case self::CMD_WRITE:
				return $composter->cmd_write() ;
			break ;

			case self::CMD_READ:
				return $composter->cmd_read($this->len, $this->data) ;
			break ;

			case self::CMD_PREPARE:
				return $composter->cmd_search() ;
			break ;

			case self::CMD_READ_COMPLETE:
				return $composter->cmd_check() ;
			break ;

			case self::CMD_WRITE_COMPLETE:
				return $composter->cmd_expunge() ;
			break ;

		}

		return false ;
	}


	function eof() {
		return ($this->command === self::CMD_PROTO_QUIT) ;
	}

}




class module_protocol_imap {

	private $handler ;
	private $parser ;
	private $composter ;
	private $messager ;

	public function __construct($handler) {
		$this->handler = $handler ;

		$this->parser = new module_protocol_imap_parser() ;
		$this->composter = new module_protocol_imap_composter() ;
		$this->messager = new module_protocol_imap_messager() ;

		//parent::__construct() ;
	}

	public function __destruct() {
		unset($this->parser) ;
		unset($this->composter) ;
		unset($this->messager) ;

		//parent::__destruct() ;
	}

	public function data_begin($client) {

		printf("connect %s:%s\n", $client->ip, $client->port) ;

  		if ($this->messager->parse($this->parser, $this->handler)) {
            $client->write($this->messager->compose($this->composter)) ;
 		}
		$this->parser->release() ;

  		return true ;
	}

	public function data_process(&$client) {

		$buffer = &$client->buffer ;

		if ($this->parser->parse_data($buffer)) {

  			if ($this->messager->parse($this->parser, $this->handler)) {
            	$client->write($this->messager->compose($this->composter)) ;
 			} else {
 				$client->write($this->composter->error()) ;
 				$client->destroy() ;
 			}

			if ($this->messager->eof())
 				$client->destroy() ;

			$buffer = null ;
			$this->parser->release() ;
		}

       	$client->buffer_flush() ;
  		return true ;
	}

	public function data_end($client) {

		printf("disconnect %s:%s\n", $client->ip, $client->port) ;

		//return $this->data_process($client) ;
	}


}

?>