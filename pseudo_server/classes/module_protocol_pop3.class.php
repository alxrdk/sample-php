<?php

interface module_protocol_pop3_session {
	const STATE_INIT = 0 ;
	const STATE_EHLO = 1 ;
	const STATE_AUTH = 2 ;
	const STATE_STAT = 3 ;
	const STATE_LIST = 4 ;
	const STATE_CMD = 5 ;


}

class module_protocol_pop3_parser implements module_protocol_pop3_session {

	public $state = NULL ;

	const IMAGE_HEADER = '' ;

	private $read_offset = NULL ;
	private $read_size = NULL ;
	private $msg_count ;

	private $return_mode = 0 ;

	public $stream ;
	public $metadata ;
	public $command ;
	public $params ;

	public function __construct() {

		//$this->state = self::STATE_EHLO ;
		$this->stream = fopen("php://memory", 'r+b') ;
	}

	public function __destruct() {

		fclose($this->stream) ;
		unset($this->stream) ;
	}

	public function release() {

		$this->buffer = null ;
		$this->__destruct() ;
		$this->__construct() ;

	}

	public function parse_data($data) {

   		$buf = &$this->buffer ;
   		$buf_offset = strlen($buf) ;
   		$buf.= $data ;

		if (($ln_pos = strpos($buf, "\n", $buf_offset)) === false)
			return false ;

		$cmd_line = trim(substr($buf, $buf_offset, $ln_pos - $buf_offset)) ;

		switch($this->state) {

			case self::STATE_EHLO:

				if (preg_match('/^AUTH PLAIN ([A-F0-9]{32})/', $cmd_line, $m)) {					$this->metadata = $m[1] ;					return true ;
				} else
					return false ;

			break ;

			case self::STATE_STAT:

				if (preg_match('/^STAT/', $cmd_line)) {					return true ;
				} else
					return false ;

			break ;

			case self::STATE_LIST:

				if (preg_match('/^LIST/', $cmd_line)) {
					return true ;
				} else
					return false ;

			break ;

			case self::STATE_CMD:

				if (preg_match('/^(RETR|TOP|DELE|QUIT)(?:\s(\d+)|)/', $cmd_line, $m)) {

					$this->command = $m[1] ;
					$this->params = array_slice($m, 2) ;
					return true ;

				} else
					return false ;

			break ;
		}

		return false ;
	}

}

class module_protocol_pop3_composter {

	const MSG_EHLO = 'POP3 server ready' ;
	const MSG_OK = '' ;
	const MSG_USER = '%s name is a valid mailbox' ;
	const MSG_LIST = '%s messages' ;
	const MSG_DATA = '%s octets' ;

	public function __construct() {
	}

	public function __destruct() {
	}

	public function msg($msg) {

		return sprintf("+OK %s\r\n", $msg) ;
	}

	public function error() {

		return sprintf("+ERR\r\n") ;
	}

	public function init_session() {		return $this->msg(self::MSG_EHLO) ;	}

	public function cmd_user($user) {
		return $this->msg(sprintf(self::MSG_USER, $user)) ;
	}

	public function cmd_stat($num, $length) {
		return $this->msg(sprintf("%d %d", $num, $length)) ;
	}

	public function cmd_list($messages) {
		$str = sprintf(self::MSG_LIST."\n", sizeof($messages)) ;
		foreach($messages as $message) {			$str.= sprintf("%s %d\n", $message['name'], $message['size']) ;
		}
		$str.= "\n.\n" ;

		return $this->msg($str) ;
	}

	public function cmd_data($data, $length) {
		return $this->msg(sprintf(self::MSG_DATA."\n%s\n.\n", $length, $data)) ;
	}

}

class module_protocol_pop3_messager implements module_protocol_pop3_session {

	const CMD_HEARTBEAT = 9 ;
	const CMD_READ = 3 ;
	const CMD_READ_COMPLETE = 4 ;
	const CMD_PREPARE = 6 ;
	const CMD_WRITE = 7 ;
	const CMD_WRITE_COMPLETE = 8 ;

	const CMD_PROTO_EHLO = -1 ;
	const CMD_PROTO_USER = -2 ;
	const CMD_PROTO_LIST = -3 ;
	const CMD_PROTO_TOP = -4 ;
	const CMD_PROTO_QUIT = -5 ;

 	const MODE_BASE64 = 2 ;

	private $metadata = NULL ;
	private $command = NULL ;
	private $offset = NULL ;
	private $len = NULL ;
	private $mode = NULL ;
	public $buffer = NULL ;
	private $data = NULL ;
	private $count = NULL ;

	public function parse(&$parser, &$handler) {

		if ($parser->state == NULL) {
			$parser->state = self::STATE_EHLO ;
			$this->command = self::CMD_PROTO_EHLO ;
			return true ;
		}

		if ($parser->state == self::STATE_EHLO) {
			$metadata = &$parser->metadata ;
			if (!preg_match('/^[0-9A-F]{32}$/', $metadata))
				return false ;

			$this->metadata = $metadata ;
			$parser->state = self::STATE_STAT ;
			$this->command = self::CMD_PROTO_USER ;
			return true ;
		}

		if ($parser->state == self::STATE_STAT) {

			$this->len = $handler->heartbeat($this->metadata) ;
			$parser->state = self::STATE_LIST ;
			$this->command = self::CMD_HEARTBEAT ;
			return true ;
		}

		if ($parser->state == self::STATE_LIST) {

			$this->command = self::CMD_PROTO_LIST ;
			$parser->state = self::STATE_CMD ;
			return true ;
		}

		if ($parser->state == self::STATE_CMD) {

			$params = $parser->params ;

			switch($parser->command) {
				case 'RETR':

					if (!isset($params[0]))
						return false ;

					if ($params[0] <= ($this->count - 3)) {

						if (is_null($this->metadata) || is_null($this->offset) || is_null($this->len) || is_null($this->mode))
							return false ;

						$this->data = $handler->read($this->metadata, $this->offset, $this->len, $this->mode) ;
						$this->command = self::CMD_READ ;
						return true ;

					} else if ($params[0] == ($this->count - 2)) {

						$handler->read_complete($this->metadata) ;
						$this->command = self::CMD_READ_COMPLETE ;
                	}

				break ;
				case 'TOP':

					if (!isset($params[0]))
						return false ;

					if (is_null($this->mode)) {
						$this->len = NULL ;						$this->mode = $params[0] ;
						if ($this->mode != self::MODE_BASE64)
							return false ;

						$this->command = self::CMD_PROTO_TOP ;
						return true ;					}

					if (is_null($this->offset)) {
						$this->offset = $params[0] ;
						$this->command = self::CMD_PROTO_TOP ;
						return true ;
					}

					if (is_null($this->len)) {
						$this->len = $params[0] ;
						$this->command = self::CMD_PROTO_TOP ;
						return true ;
					}


				break ;

				case 'QUIT':

					$this->command = self::CMD_PROTO_QUIT ;
					return true ;

				break ;

			}

		}

		return false ;
	}

	public function compose(&$composter) {

		switch ($this->command) {
			case self::CMD_PROTO_EHLO:
				return $composter->init_session() ;
			break ;

			case self::CMD_PROTO_USER:
				return $composter->cmd_user($this->metadata) ;
			break ;

			case self::CMD_HEARTBEAT:
				$length = $this->len ;

				srand() ;
				$num = (($num = rand(2, 32)) % ($length?2:1))?$num:$num-1 ;

				return $composter->cmd_stat($num, $length) ;
			break ;

			case self::CMD_PROTO_LIST:

				srand() ;
				$num = rand(4, 32) ;
				$this->count = $num ;

				for($i = 1 ; $i <= $num ; $i++)
					$messages[] = array('name' => $i, 'size' => rand(100, 32000)) ;

				return $composter->cmd_list($messages) ;
			break ;

			case self::CMD_READ:

				if ($this->mode == self::MODE_BASE64)
					$this->data = base64_encode($this->data) ;

				$length = strlen($this->data) ;

				return $composter->cmd_data($this->data, $length) ;
			break ;

			case self::CMD_READ_COMPLETE:
				return $composter->msg(NULL) ;
			break ;

			case self::CMD_PROTO_TOP:
				return $composter->msg(NULL) ;
			break ;

			case self::CMD_PROTO_QUIT:
				return $composter->msg(NULL) ;
			break ;

		}

		return false ;
	}


	function eof() {		return ($this->command === self::CMD_PROTO_QUIT) ;
	}

}

class module_protocol_pop3 {

	private $handler ;
	private $parser ;
	private $composter ;
	private $messager ;

	public function __construct(&$handler) {
		$this->handler = $handler ;

		$this->parser = new module_protocol_pop3_parser() ;
		$this->composter = new module_protocol_pop3_composter() ;
		$this->messager = new module_protocol_pop3_messager() ;

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
 			} else { 				$client->write($this->composter->error()) ;
 				$client->destroy() ;
 			}

			if ($this->messager->eof())
 				$client->destroy() ;

			$buffer = null ;
			$this->parser->release() ;

		}

  		return true ;
	}

	public function data_end($client) {

		printf("disconnect %s:%s\n", $client->ip, $client->port) ;

		//return $this->data_process($client) ;
	}

}






?>