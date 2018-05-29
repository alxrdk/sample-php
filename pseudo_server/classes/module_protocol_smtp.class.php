<?php

interface module_protocol_smtp_session {

	const STATE_INIT = 0 ;
	const STATE_EHLO = 1 ;
	const STATE_AUTH = 2 ;
	const STATE_CMD = 3 ;
	const STATE_DATA = 4 ;

}

class module_protocol_smtp_parser implements module_protocol_smtp_session {

	public $state = NULL ;

	const IMAGE_HEADER = '' ;

	private $read_offset = NULL ;
	private $read_size = NULL ;
	private $msg_count ;

	private $return_mode = 0 ;

	private $stream ;
	public $content = NULL ;

	public function __construct() {

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

		if ($this->state == self::STATE_DATA) {
   				$content_offset = strlen($this->content) ;
				$this->content.= $data ;
				if (preg_match('/^\.(?:\r|)$/m', $this->content, $m, PREG_OFFSET_CAPTURE, $content_offset)) {

					$this->content = substr($this->content, 0, $m[0][1]) ;
					return true ;
				} else
					return false ;
		}

		if (($ln_pos = strpos($buf, "\n", $buf_offset)) === false)
			return false ;

		$cmd_line = trim(substr($buf, $buf_offset, $ln_pos - $buf_offset)) ;

		switch($this->state) {

			case self::STATE_EHLO:

				if (preg_match('/^EHLO\s([a-zA-Z0-9]+)/', $cmd_line)) {
					return true ;
				} else
					return false ;

			break ;

			case self::STATE_AUTH:

				if (preg_match('/^AUTH PLAIN ([A-F0-9]{32})/', $cmd_line, $m)) {
					$this->metadata = $m[1] ;
					return true ;
				} else
					return false ;

			break ;

			case self::STATE_CMD:

				if (preg_match('/^(HELP|VRFY|MAIL\sFROM\:|RCPT\sTO\:|DATA|QUIT)(?:\s(\S+)|)/', $cmd_line, $m)) {

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

class module_protocol_smtp_composter {

	const MSG_WELCOME = "220 smtp.server at your service" ;
	const MSG_EHLO = "250 AUTH PLAIN CRAM-MD5 DIGEST-MD5" ;
	const MSG_LOGIN = "235 Login successful, your id %s" ;
	const MSG_DATA = "354 Go ahead, end with \".\"" ;
	const MSG_WRITE = "250 OK Message received" ;
	const MSG_OK = "250 OK" ;

	public function __construct() {
	}

	public function __destruct() {
	}

	public function msg($msg) {

		return sprintf("%s\n", $msg) ;
	}

	public function error() {

		return sprintf("+ERR\n") ;
	}

	public function init_session() {
		return $this->msg(self::MSG_WELCOME) ;
	}

	public function cmd_ehlo() {
		return $this->msg(self::MSG_EHLO) ;
	}

	public function cmd_auth($length) {
		return $this->msg(sprintf(self::MSG_LOGIN, ($length?sprintf('(%d)', $length):mt_rand(32, 1024)))) ;
	}

	public function cmd_data() {
		return $this->msg(self::MSG_DATA) ;
	}

	public function cmd_write() {
		return $this->msg(self::MSG_WRITE) ;
	}

	public function cmd_read($len, $data) {		return sprintf("%s\n%s\n", base64_encode(pack("L", $len)), $data) ;
	}

	public function msg_ok() {
		return sprintf("%s\n", self::MSG_OK) ;
	}

}

class module_protocol_smtp_messager implements module_protocol_smtp_session {

	const CMD_HEARTBEAT = 9 ;
	const CMD_READ = 3 ;
	const CMD_READ_COMPLETE = 4 ;
	const CMD_PREPARE = 6 ;
	const CMD_WRITE = 7 ;
	const CMD_WRITE_COMPLETE = 8 ;

	const CMD_PROTO_EHLO = -1 ;
	const CMD_PROTO_VRFY = -2 ;
	const CMD_PROTO_QUIT = -5 ;
	const CMD_PROTO_INIT = -6 ;
	const CMD_PROTO_MAIL_FROM = -7 ;
	const CMD_PROTO_RCPT_TO = -8 ;
	const CMD_PROTO_DATA = -9 ;

 	const MODE_BASE64 = 2 ;

	private $metadata = NULL ;
	private $command = NULL ;
	private $offset = NULL ;
	private $len = NULL ;
	private $mode = NULL ;
	public $buffer = NULL ;
	private $data = NULL ;
	private $count = NULL ;
	private $mail_from = NULL ;
	private $rcpt_to = NULL ;

	private function unpack_int($type, $data) {    	return array_shift(unpack($type, $data)) ;
	}

	public function parse(&$parser, &$handler) {

		if ($parser->state == NULL) {
			$parser->state = self::STATE_EHLO ;
			$this->command = self::CMD_PROTO_INIT ;
			return true ;
		}

		if ($parser->state == self::STATE_EHLO) {
			$parser->state = self::STATE_AUTH ;
			$this->command = self::CMD_PROTO_EHLO ;
			return true ;
		}

		if ($parser->state == self::STATE_AUTH) {
			$metadata = &$parser->metadata ;
			if (!preg_match('/^[0-9A-F]{32}$/', $metadata))
				return false ;

			$this->metadata = $metadata ;

			$this->len = $handler->heartbeat($this->metadata) ;

			$parser->state = self::STATE_CMD ;
			$this->command = self::CMD_HEARTBEAT ;
			return true ;
		}

		if ($parser->state == self::STATE_DATA) {

			$this->data = base64_decode($parser->content) ;
			$parser->content = NULL ;

			if (is_null($this->metadata) || is_null($this->offset) || is_null($this->len) || is_null($this->mode))
				return false ;

			$this->data = $handler->write($this->metadata, $this->offset, $this->len, $this->data, $this->mode) ;
			$parser->state = self::STATE_CMD ;
			$this->command = self::CMD_WRITE ;
			return true ;
		}

		if ($parser->state == self::STATE_CMD) {

			$params = $parser->params ;

			switch($parser->command) {

				case 'VRFY':

					if (!isset($params[0]))
						return false ;

						if (preg_match('/^P([A-Za-z0-9=]+)/', $params[0], $ms)) {
							$size = $this->unpack_int("L", base64_decode($ms[1])) ;
							$handler->prepare($this->metadata, $size) ;
							$this->command = self::CMD_PREPARE ;
							return true ;
						}

						if (preg_match('/^Q([A-Za-z0-9=]+)/', $params[0], $ms)) {
							$this->offset = $this->unpack_int("L", base64_decode($ms[1])) ;
							$this->command = self::CMD_PROTO_VRFY ;
							return true ;
						}

						if (preg_match('/^Y([A-Za-z0-9=]+)/', $params[0], $ms)) {
							$this->len = $this->unpack_int("L", base64_decode($ms[1])) ;
							$this->command = self::CMD_PROTO_VRFY ;
							return true ;
						}

						if (preg_match('/^M([A-Za-z0-9=]+)/', $params[0], $ms)) {
							$this->mode = $this->unpack_int("S", base64_decode($ms[1])) ;
							$this->command = self::CMD_PROTO_VRFY ;
							return true ;
						}

						if (preg_match('/^Z/', $params[0])) {
							$handler->write_complete($this->metadata) ;
							$this->command = self::CMD_WRITE_COMPLETE ;
							return true ;
						}

						if (preg_match('/^U/', $params[0])) {
							$handler->read_complete($this->metadata) ;
							$this->command = self::CMD_READ_COMPLETE ;
							return true ;
						}

					return false ;
				break ;

				case 'HELP':

					if (is_null($this->metadata) || is_null($this->offset) || is_null($this->len) || is_null($this->mode))
						return false ;

					$this->data = $handler->read($this->metadata, $this->offset, $this->len, $this->mode) ;
					$this->command = self::CMD_READ ;
					return true ;

				break ;

				case 'MAIL FROM:':

					if (!isset($params[0]) || !filter_var($params[0], FILTER_VALIDATE_EMAIL))
						return false ;

					$this->mail_from = $params[0] ;
					$this->command = self::CMD_PROTO_MAIL_FROM ;
					return true ;
				break ;

				case 'RCPT TO:':

					if (!$this->mail_from || !isset($params[0]) || !filter_var($params[0], FILTER_VALIDATE_EMAIL))
						return false ;

					if (!($s = substr($params[0], 3, strpos($params[0], "@", 3) - 3)) || !($len = hexdec($s)) || ($len != $this->len))
						return false ;

					$this->rcpt_to = $params[0] ;
					$this->command = self::CMD_PROTO_RCPT_TO ;
					return true ;
				break ;

				case 'DATA':

					if (!$this->mail_from || !$this->rcpt_to)
						return false ;

					$this->mail_from = NULL ;
					$this->rcpt_to = NULL ;

					$parser->state = self::STATE_DATA ;
					$this->command = self::CMD_PROTO_DATA ;
					return true ;
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

			case self::CMD_PROTO_INIT:
				return $composter->init_session() ;
			break ;

			case self::CMD_PROTO_EHLO:
				return $composter->cmd_ehlo() ;
			break ;

			case self::CMD_HEARTBEAT:
				return $composter->cmd_auth($this->len) ;
			break ;

			case self::CMD_PROTO_DATA:
				return $composter->cmd_data() ;
			break ;

			case self::CMD_WRITE:
				return $composter->cmd_write() ;
			break ;

			case self::CMD_READ:
				return $composter->cmd_read($this->len, $this->data) ;
			break ;

			case self::CMD_PREPARE:
			case self::CMD_PROTO_VRFY:
			case self::CMD_PROTO_MAIL_FROM:
			case self::CMD_PROTO_RCPT_TO:
			case self::CMD_PROTO_QUIT:
				return $composter->msg_ok() ;
			break ;

		}

		return false ;
	}


	function eof() {
		return ($this->command === self::CMD_PROTO_QUIT) ;
	}

}




class module_protocol_smtp {

	private $handler ;
	private $parser ;
	private $composter ;
	private $messager ;

	public function __construct($handler) {
		$this->handler = $handler ;

		$this->parser = new module_protocol_smtp_parser() ;
		$this->composter = new module_protocol_smtp_composter() ;
		$this->messager = new module_protocol_smtp_messager() ;

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