<?php

namespace protocol ;

interface ibbdx {
	const SIGNATURE = 'BBDX' ;

	const IDLE = 15 ;

	const BLOCK_CLOSE = 0 ;
	const BLOCK_KEEP_ALIVE = 1 ;
	const BLOCK_DATA = 2 ;
	const BLOCK_KEYGEN = 3 ;
	const BLOCK_CRYPT = 4 ;
	const BLOCK_HANDSHAKE = 5 ;

	const DATA_TYPE_RAW = 0 ;
	const DATA_TYPE_BSON = 1 ;
	const DATA_TYPE_MSGPACK = 2 ;

	const SIGN_TYPE_RSA2048_SHA512 = 1 ;

	const FLAG_GZIP = 0x01 ;
	const FLAG_ROUTING = 0x02 ;

	const RESULT_SUCCESS = 0 ;
	const RESULT_PARSING_ERROR = 1 ;
	const RESULT_SIGN_ERROR = 2 ;
	const RESULT_NOCRYPT_DENIED = 3 ;

}

namespace protocol\bbdx ;

abstract class stream {
	protected $_complited ;

	protected $_stream ;

	protected $_stream_length ;

	public function __construct(&$stream) {
		$this->_stream = $stream ;

		//$this->_complited = true ;
		$this->_stream_length = $this->_length() ;
	}

	public function __destruct() {

	}

	protected function _read($len, $fixed = false) {
		if ($len == 0)
			return false ;

		if (($buf = fread($this->_stream, $len)) === false)
			return false ;

		if ($fixed && strlen($buf) != $len)
			return false ;

		return $buf ;
	}

	protected function _write(&$buffer, $length = NULL) {
		if (is_null($length))
			$length = strlen($buffer) ;

		$written = 0 ;

		while($written < $length)
			$written+= fwrite($this->_stream, substr($buffer, $written), $length - $written) ;

		$this->_stream_length+= $written ;

		return true ;
	}

	protected function _jump($offset) {

		return fseek($this->_stream, $offset) ;
	}

	protected function _flush($offset) {
		$length = $this->_length() ;

		$buf_size = $length - $offset ;

		if ($buf_size > 0) {

			if (($buf = $this->_read($buf_size)) === false)
				return false ;

			ftruncate($this->_stream, $buf_size) ;
			rewind($this->_stream) ;
			$this->_stream_length = 0 ;
			return $this->_write($buf, $buf_size) ;
		}

		$this->_stream_length = $buf_size ;
		return ftruncate($this->_stream, $buf_size) ;
	}

	protected function _getpos() {
		return ftell($this->_stream) ;
	}

	protected function _length() {
		$stat = fstat($this->_stream) ;
		return $stat['size'] ;
	}

	protected function _unpack($type, &$data) {		$arr = unpack($type, $data) ;		return array_shift($arr) ;
	}

	private function _padding() {
		$start = $this->get_offset() ;
		$offset = $this->_getpos() ;

		$padding = 16 - (($offset - $start) % 16) & 0x0F ;

		return array($padding, $offset) ;
	}

	protected function _padding_write() {

		list($padding, $offset) = $this->_padding() ;

		$buf = str_repeat(chr($padding), $padding) ;
		$this->_write($buf, $padding) ;

     	return $offset + $padding ;
	}

	protected function _padding_skip() {

		list($padding, $offset) = $this->_padding() ;

//		if ($this->_length() < $offset + $padding)
//			return $offset ;

		if ($padding > 0)
			$this->_jump($offset + $padding) ;

     	return $offset + $padding ;
	}

	public function is_complited() {
		return $this->_complited ;	}
}

namespace protocol\bbdx ;

class handshake extends stream implements \protocol\ibbdx {
	const CHUNK_SIZE = 24 ;

	public $idle ;
	public $source_id ;

	private $_offset ;

	public function __construct(&$stream, $idle = NULL, $source_id = NULL) {
		$this->stream = $stream ;
		$this->idle = $idle ;
		$this->source_id = $source_id ;

		parent::__construct($stream) ;

	}
	public function __destruct() {
		parent::__destruct() ;
	}

	public function get_chunk_size() {

		return self::CHUNK_SIZE ;
	}

	public function parse() {
		$this->_offset = $this->_getpos() ;

		$buf = $this->_read(strlen(self::SIGNATURE), true) ;

		if ($buf != self::SIGNATURE)
			return false ;

		if (($buf = $this->_read(4, true)) === false)
			return false ;

		$this->idle = $this->_unpack('L', $buf) ;

		if (($buf = $this->_read(16, true)) === false)
			return false ;

		$this->source_id = $buf ;

		$this->_complited = true ;

		return true ;
	}

	public function compose() {

		$this->_offset = $this->_getpos() ;

		if (empty($this->idle))
			return false ;
		if (empty($this->source_id))
			return false ;

		$this->_complited = true ;

		$data = self::SIGNATURE.pack("L", $this->idle).$this->source_id ;

		if (strlen($data) != self::CHUNK_SIZE)
			return false ;

		$this->_complited = true ;

		if ($this->_write($data, self::CHUNK_SIZE) === false)
			return false ;

		return true ;
	}

	public function get_offset() {

		return $this->_offset ;
	}

	public static function factory(&$stream, $idle = NULL, $source_id = NULL) {
		return new self($stream, $idle, $source_id) ;	}

}

namespace crypt\hash ;

class stream {

	private $_ctx ;
	private $_hash ;
	private $_stream ;
	private $_offset ;

	public function __construct(&$stream, $algo) {
		$this->_stream = $stream ;
		$this->_init($algo) ;
	}

	private function _init($algo) {

		$this->_ctx = hash_init($algo) ;
		return is_resource($this->_ctx) ;
	}

	public function jump() {

		return $this->_offset = ftell($this->_stream) ;
	}

	public function update() {

		fseek($this->_stream, $this->_offset) ;
		return hash_update_stream($this->_ctx, $this->_stream) ;
	}

	public function close() {

		$this->_hash = hash_final($this->_ctx, true) ;
		unset($this->_ctx) ;

		return $this->_hash ;
	}

	public function get() {
		return $this->_hash ;	}

	public static function factory($stream, $algo) {

		return new self($stream, $algo) ;
	}

}


namespace protocol\bbdx\block ;

abstract class prototype extends \protocol\bbdx\stream implements \protocol\ibbdx {
	protected $_state ;

	protected $_length ;

	protected $_offset ;
	protected $_processed ;

	const STATE_INIT = 0x01 ;
	const STATE_HEADER = 0x02 ;
	const STATE_DATA = 0x03 ;
	const STATE_COMPLITED = 0x04 ;

	const HEADER_CHUNK_SIZE = 8 ;

	public function __construct(&$stream) {

		$this->_offset = $this->_getpos() ;

		parent::__construct($stream) ;
	}

	public function is_header() {

		return $this->_state == self::STATE_HEADER ;
	}

	public function is_data() {

		return $this->_state == self::STATE_DATA ;
	}

	public function is_complited() {

		return $this->_state == self::STATE_COMPLITED ;
	}

	protected function parse_header() {
		if (($buf = $this->_read(4, true)) === false)
			return false ;

		$length = $this->_unpack('L', $buf) ;

		if (($buf = $this->_read(4, true)) === false)
			return false ;

		$crc = $this->_unpack('L', $buf) ;

		if ($crc != crc32(pack('L', $length)))
			return false ;

		$this->_length = $length ;

		return true ;
	}

	protected function compose_header() {

		$crc = crc32(pack('L', $this->_length)) ;

		$data = pack('L', $this->_length).pack('L', $crc) ;

		if ($this->_write($data, self::HEADER_CHUNK_SIZE) === false)
			return false ;

		return true ;
	}

	protected function get_chunk_size() {
		if ($this->_state == self::STATE_INIT)
			return self::DATA_HEADER_CHUNK_SIZE ;

		elseif ($this->_state == self::STATE_DATA)
			return $this->_buffer_size() ;

		return 0 ;
	}

	protected function parse() {
		if ($this->_state == self::STATE_INIT)
			if ($this->parse_header()) {

				$this->_offset = $this->_getpos() ;
				$this->_state = self::STATE_HEADER ;

				return true ;
			} else return false ;

		if ($this->_state == self::STATE_HEADER) {
			$this->_processed = 0 ;
			$this->_state = self::STATE_DATA ;
			return true ;
		}

		if ($this->_state == self::STATE_DATA) {

			$offset = $this->_getpos() ;

			if (!$this->parse_data())
				return false ;

			$this->_processed+= $this->_getpos() - $offset ;

			if ($this->_getpos() - $this->_offset == min($this->_length, $this->_length() - $this->_offset)) {

				if ($this->_processed == $this->_length)
					$this->_state = self::STATE_COMPLITED ;
            }

			return true ;
		}

  		if ($this->_state == self::STATE_COMPLITED) {

			$this->_complited = true ;
			return true ;
		}

		return false ;
	}

	public function compose() {

		if ($this->_state == self::STATE_INIT) {

			if (!$this->compose_header())
				return false ;

			$this->_state = self::STATE_HEADER ;
           	$this->_offset = $this->_getpos() ;

			//return true ;
		}

		if ($this->_state == self::STATE_HEADER) {

			$this->_state = self::STATE_DATA ;
			//return true ;
		}

		if ($this->_state == self::STATE_DATA) {

			$this->compose_data() ;

			if ($this->_getpos() - $this->_offset == $this->_length) {
				$this->_state = self::STATE_COMPLITED ;

            } else
				$this->_state = self::STATE_DATA ;

			return true ;
		}

		if ($this->_state == self::STATE_COMPLITED)
			return true ;
	}

}

namespace protocol\bbdx\block ;

class keygen extends prototype implements \protocol\ibbdx {

	private $_data ;

	public function __construct(&$stream, $data = null, $length = NULL) {

		$this->_stream = $stream ;

		$this->_state = self::STATE_INIT ;

		$this->_data = $data ;
		$this->_length = $length ;
		parent::__construct($stream) ;
	}

	public function __destruct() {

		parent::__destruct() ;
	}

	protected function _buffer_size() {

		return $this->_length ;
	}

	protected function parse_data() {

		if (($buf = $this->_read($this->_length, true)) === false)
			return false ;

		$this->_data = $buf ;

		return true ;
	}

	protected function compose_data() {

		if ($this->_write($this->_data, $this->_length) === false)
			return false ;

		return true ;
	}

	public function get_chunk_size() {

		return parent::get_chunk_size() ;
	}

	public function parse() {

		return parent::parse() ;
	}

	public function compose() {

		return parent::compose() ;
	}

	public function get_data() {
		return $this->_data ;
	}

	public static function factory(&$stream, $data = NULL, $length = NULL) {

		return new self($stream, $data, $length) ;
	}

}

namespace protocol\bbdx\block ;

class crypt extends \protocol\bbdx\stream implements \protocol\ibbdx {

	private $_hash ;

	const CHUNK_SIZE = 20 ;

	public function __construct(&$stream, $hash) {

		$this->_stream = $stream ;

		$this->_hash = $hash ;
	}

	public function __destruct() {

		parent::__destruct() ;
	}

	public function get_chunk_size() {
		return self:: CHUNK_SIZE ;
	}

	public function parse() {

		if (($buf = $this->_read(20, true)) === false)
			return false ;

		$this->_hash = $buf ;

		$this->_complited = true ;

		return true ;
	}

	public function compose() {

		if ($this->_write($this->_hash, 20) === false)
			return false ;

		$this->_complited = true ;

		return true ;
	}

	public function get_key_hash() {
		return $this->_hash ;
	}


	public static function factory(&$stream, $key_hash = NULL) {

		return new self($stream, $key_hash) ;
	}


}

namespace protocol\bbdx\block ;

class data extends prototype implements \protocol\ibbdx {
	private $_format ;

	private $_flags ;

	private $_sign_type ;

	private $_data_stream ;

	private $_readed ;

	private $_sign_length ;

	private $_sign_data ;

	private $_hash_algo ;

	private $_rsa_len ;

	private $_buffer ;

	private $_gzip_filter ;


	const STATE_SIGN_HEADER = 0x05 ;
	const STATE_SIGN_DATA = 0x06 ;

	const DATA_HEADER_CHUNK_SIZE = 14 ;
	const SIGN_HEADER_CHUNK_SIZE = 8 ;

	const BUFFER_SIZE = 65535 ;


	public function __construct(&$stream, $format = NULL, $flags = NULL, $length = NULL, $sign_type = NULL) {
		$this->_state = self::STATE_INIT ;		$this->_length = 0 ;
		$this->_readed = 0 ;

		$this->_stream = $stream ;

		$this->_format = $format ;
		$this->_flags = $flags ;
		$this->_length = $length ;
		$this->_sign_type = $sign_type ;

		if ($this->_sign_type == self::SIGN_TYPE_RSA2048_SHA512) {
			$this->_hash_algo = 'sha512' ;
			$this->_rsa_len = 2048 ;
		}

		//$this->_hash = \crypt\hash\stream::factory($this->_stream, $this->_hash_algo) ;

		parent::__construct($stream) ;
	}

	public function __destruct() {

		unset($this->_struct) ;
		parent::__destruct() ;
	}

	protected function parse_header() {
		if (($buf = $this->_read(2, true)) === false)
			return false ;

		$this->_format = $this->_unpack('S', $buf) ;

		if (!in_array($this->_format, array(self::DATA_TYPE_RAW, self::DATA_TYPE_BSON, self::DATA_TYPE_MSGPACK)))
			return false ;

		if (($buf = $this->_read(4, true)) === false)
			return false ;

		$this->_flags = $this->_unpack('L', $buf) ;

/*
		if (($buf = $this->_read(2, true)) === false)
			return false ;

		$this->_sign_type = $this->_unpack('S', $buf) ;

		if (!in_array($this->_sign_type, array(self::SIGN_TYPE_RSA2048_SHA512)))
			return false ;
*/

		return parent::parse_header() ;
	}

	protected function compose_header() {

		$data = pack('S', $this->_format).pack('L', $this->_flags) ;

		//$data.= pack('S', $this->_sign_type) ;

/*
		if (is_null($this->_length))
			if (!is_null($this->_buf))
				$length = strlen($this->_buf) ;
			else return false ;
*/

		if ($this->_write($data, self::DATA_HEADER_CHUNK_SIZE - parent::HEADER_CHUNK_SIZE) === false)
			return false ;

		return parent::compose_header() ;
	}

	protected function _buffer_size() {
		return min($this->_length, self::BUFFER_SIZE) ;	}

	protected function parse_data() {

//		if ($this->_state == self::STATE_HEADERS)
//			$this->_readed = 0 ;

		if (($buf = $this->_read($this->_buffer_size())) === false)
			return false ;

		$this->_buffer = $buf ;

		//fwrite($this->_data_stream, $buf) ;

		return true ;
	}

	protected function compose_data() {

		if ($this->_write($this->_buffer, strlen($this->_buffer)) === false)
			return false ;

		return true ;
	}

	private function parse_sign_header() {
		if (($buf = $this->_read(4, true)) === false)
			return false ;

		$this->_sign_length = $this->_unpack('L', $buf) ;

		if (($buf = $this->_read(4, true)) === false)
			return false ;

		$crc = $this->_unpack('L', $buf) ;

		if ($crc != crc32($this->_sign_length))
			return false ;

		return true ;
	}

	private function compose_sign_header() {

		$crc = crc32($this->_sign_length) ;

		$data = pack('L', $this->_sign_length).pack('L', $crc) ;

		if ($this->_write($data, self::SIGN_HEADER_CHUNK_SIZE) === false)
			return false ;

		return true ;
	}

	private function parse_sign_data() {

		if (($buf = $this->read($this->_sign_length)) === false)
			return false ;

		$this->_sign_data = $buf ;

		return true ;
	}

	private function compose_sign_data() {

		if ($this->_write($this->_sign_data, $this->_sign_length) === false)
			return false ;

		return true ;
	}

	private function compose_sign() {
		$hash = $this->_hash->close() ;
		unset($this->_hash) ;

		$this->_sign_data = $hash ;
		$this->_sign_length = strlen($hash) ;
/*
		$cm = \crypt\master::factory() ;

		if (!$cm->load_key_private())
			return false ;

		if (!$cm->sign_hash($hash))
			return false ;

		$this->_sign_data = $sec->get_sign_data() ;
		$this->_sign_length = $sec->get_sign_len() ;
*/
		if (!$this->compose_sign_header())
			return false ;

		if (!$this->compose_sign_data())
			return false ;

		return true ;
	}

	public function get_chunk_size() {
			if ($this->_state == self::STATE_SIGN_HEADER)
				return self::SIGN_HEADER_CHUNK_SIZE ;

			elseif ($this->_state == self::STATE_SIGN_DATA)
				return $this->_sign_length ;

		return parent::get_chunk_size() ;	}

	private function _gzip_params() {
		return array('level' => 6, 'window' => 15, 'memory' => 9) ;
	}

	public function parse() {
		if ($this->_state == self::STATE_SIGN_HEADER)

			if ($this->parse_sign_header()) {
				$this->_state = self::STATE_SIGN_DATA ;
				return true ;
			} else return false ;

		if ($this->_state == self::STATE_SIGN_DATA)

			if ($this->parse_sign_data()) {
				$this->_state = self::STATE_COMPLITED ;
				$this->_complited = true ;
				return true ;
			} else return false ;

		$status = parent::parse() ;
/*
		if ($status && $this->_flags & self::FLAG_GZIP)			if ($this->_state == self::STATE_HEADER) {
				$this->_gzip_filter = stream_filter_append($this->_stream, 'zlib.deflate', STREAM_FILTER_READ, $this->_gzip_params()) ;
			} elseif ($this->_state == self::STATE_COMPLITED)
				stream_filter_remove($this->_gzip_filter) ;
*/
		return $status ;
	}
	public function compose($eof = false) {
		$status = parent::compose($eof) ;


		if ($status && $this->_flags & self::FLAG_GZIP)
			if ($this->_state == self::STATE_HEADER) {
				$this->_gzip_filter = stream_filter_append($this->_stream, 'zlib.deflate', STREAM_FILTER_WRITE, $this->_gzip_params()) ;
			} elseif ($this->_state == self::STATE_COMPLITED)
				stream_filter_remove($this->_gzip_filter) ;


		//if ($status && $this->_flags & self::FLAG_GZIP)

		return $status ;
	}

	public function write_buffer(&$buf, $length = NULL) {
		if (is_null($length))
			$length = strlen($buf) ;

		$this->_length+= $length ;

		return $this->_write($buf) ;	}

	public function get_buffer() {

		return $this->_buffer ;
	}

	public function get_format() {

		return $this->_format ;
	}

	public function get_flags() {

		return $this->_flags ;
	}

	public static function factory(&$stream, $format = NULL, $flags = NULL, $sign_type = NULL) {

		return new self($stream, $format, $flags, $sign_type) ;
	}

}

namespace protocol\bbdx\block ;

class result extends \protocol\bbdx\stream implements \protocol\ibbdx {

	private $_code ;
	private $_close ;

	const CHUNK_SIZE = 2 ;

	public function __construct(&$stream, $code, $close) {

		$this->_stream = $stream ;

		$this->_code = $code ;
		$this->_close = $close ;
	}

	public function __destruct() {

		parent::__destruct() ;
	}

	public function get_chunk_size() {

		return self:: CHUNK_SIZE ;
	}

	public function parse() {

		if (($buf = $this->_read(1, true)) === false)
			return false ;

		$this->_code = $this->_unpack('C', $buf) ;

		if (($buf = $this->_read(1, true)) === false)
			return false ;

		$this->_close = $this->_unpack('C', $buf) ;

		$this->_complited = true ;

		return true ;
	}

	public function compose() {

		$data = pack('C', $this->_code).pack('C', $this->_close) ;

		if ($this->_write($data, self::CHUNK_SIZE) === false)
			return false ;

		$this->_complited = true ;

		return true ;
	}

	public function get_code() {

		return $this->_code ;
	}

	public function get_close() {

		return $this->_close ;
	}

	public static function factory(&$stream, $code = NULL, $close = NULL) {

		return new self($stream, $code, $close) ;
	}

}

namespace protocol\bbdx ;

class block extends stream implements \protocol\ibbdx {
	protected $_code ;
	protected $_state ;
	protected $_params ;
	protected $_control ;

	private $_result_mode ;
	private $_result ;

	private $_offset ;

	private $_block ;

	const HEADER_CHUNK_SIZE = 1 ;	const CLOSE_CHUNK_SIZE = 1 ;
	const KEEP_ALIVE_CHUNK_SIZE = 0 ;

	const STATE_INIT = 0x01 ;
	const STATE_HEADER = 0x02 ;
	const STATE_DATA = 0x03 ;
	const STATE_COMPLITED = 0x04 ;

	public function __construct(&$stream, $result_mode = NULL, $result = NULL) {
		$this->_stream = $stream ;

		$this->_result_mode = $result_mode ;
		$this->_result = $result ;

		$this->_state = self::STATE_INIT ;
	}

	public function __destruct() {

		unset($this->_block) ;

		parent::__destruct() ;
	}

	public function get_code() {
		return $this->_code ;
	}

	public function set_code($code) {

		return $this->_code = $code ;
	}

	public function is_header() {

		return $this->_state == self::STATE_HEADER ;	}

	public function is_data() {

		return $this->_state == self::STATE_DATA ;
	}

	public function is_complited() {

		return $this->_state == self::STATE_COMPLITED ;
	}

	private function parse_header() {
		if (($buf = $this->_read(1, true)) === false)
			return false ;

		$this->_code = $this->_unpack('C', $buf) ;

		return true ;
	}

	private function compose_header() {

		$code = pack('C', $this->_code) ;

		if (($this->_write($code, 1)) === false)
			return false ;

		return true ;
	}

	private function parse_control($arr, $len) {

		if (($buf = $this->_read($len, true)) === false)
			return false ;

		$s = 0 ;
		$this->_control = array() ;
		foreach($arr as $key=>$val) {			$sbuf = substr($buf, $s, $val) ;
			$this->_control[] = $this->_unpack($key, $sbuf) ;
			$s+= $val ;
		}

		return true ;
	}

	private function compose_control() {

		$data = '' ;
		if (is_array($this->_control))
			foreach($this->_control as $val) {				list($fmt, $arg) = each($val) ;
				$data.= pack($fmt, $arg) ;
			}

		if (($this->_write($data, strlen($data))) === false)
			return false ;

		return true ;
	}

    public function close($reason) {
    	$this->_code = self::BLOCK_CLOSE ;
		$this->_control = array(array('C' => $reason)) ;

		return $this ;
    }

    public function keep_alive() {

    	$this->_code = self::BLOCK_KEEP_ALIVE ;

		return $this ;
    }

    public function keygen($data) {

    	$this->_code = self::BLOCK_KEYGEN ;

		$length = strlen($data) ;
		$this->_block = block\keygen::factory($this->_stream, $data, $length) ;

		return $this ;
    }

    public function crypt($key_hash) {

    	$this->_code = self::BLOCK_CRYPT ;
		$this->_block = block\crypt::factory($this->_stream, $key_hash) ;

		return $this ;
    }

    public function data($format = NULL, $flags = NULL, $sign_type = NULL) {

    	$this->_code = self::BLOCK_DATA ;
		$this->_block = block\data::factory($this->_stream, $format, $flags, $sign_type) ;

		return $this ;
    }

	public function get_chunk_size() {

		if ($this->_state == self::STATE_INIT)
			return self::HEADER_CHUNK_SIZE ;

		elseif ($this->_state == self::STATE_HEADER) {

			switch ($this->_code) {

				case self::BLOCK_CLOSE:

					return self::CLOSE_CHUNK_SIZE ;

				break ;

				case self::BLOCK_KEEP_ALIVE:

					return self::KEEP_ALIVE_CHUNK_SIZE ;

				break ;

				case self::BLOCK_KEYGEN:

					return block\keygen::HEADER_CHUNK_SIZE ;

				break ;

				case self::BLOCK_CRYPT:

					return block\crypt::CHUNK_SIZE ;

				break ;

				case self::BLOCK_DATA:

					return block\data::DATA_HEADER_CHUNK_SIZE ;

				break ;

				default:

					return false ;

				break ;
			}

			return 0 ;
		}

		elseif ($this->_state == self::STATE_DATA) {				if (!$this->_block instanceof block)
					return false ;
				return $this->_block->get_chunk_size() ;
		}

		elseif ($this->_state == self::STATE_COMPLITED)
			return 0 ;

		return false ;
	}

    public function parse() {
		if ($this->_state == self::STATE_INIT) {
			$this->_offset = $this->_getpos() ;

			if ($this->_result_mode) {

   				$this->_result = block\result::factory($this->_stream) ;

				if (!$this->_result->parse())
					return false ;

				if (($this->_result->get_code() !== 0) || !in_array($this->_code, array(self::BLOCK_DATA, self::BLOCK_KEYGEN))) {
					$this->_complited = true ;
					$this->_state = self::STATE_COMPLITED ;
					return true ;
				}

			} elseif (!$this->parse_header())
				return false ;

			$this->_state = self::STATE_HEADER ;
			return true ;
		}

		$this->_state = self::STATE_DATA ;

		switch($this->_code) {
			case self::BLOCK_CLOSE:

				if (!$this->_result_mode)
					if (!$this->parse_control(array('C' => 1), 1))
						return false ;

				$this->_complited = true ;
				$this->_state = self::STATE_COMPLITED ;

				return true ;
			break ;
			case self::BLOCK_KEEP_ALIVE:

				$this->_complited = true ;
				$this->_state = self::STATE_COMPLITED ;

				return true ;
			break ;

			case self::BLOCK_KEYGEN:

				if (!$this->_block instanceof block\keygen)
					$this->_block = block\keygen::factory($this->_stream) ;

				if (!$this->_block->parse())
					return false ;

				if ($this->_block->is_complited()) {

					$this->_complited = true ;
					$this->_state = self::STATE_COMPLITED ;
				}

				return true ;
			break ;

			case self::BLOCK_CRYPT:

				if (!$this->_block instanceof block\crypt)
					$this->_block = block\crypt::factory($this->_stream) ;

				if (!$this->_block->parse())
					return false ;

				if ($this->_block->is_complited()) {

					$this->_complited = true ;
					$this->_state = self::STATE_COMPLITED ;
				}

				return true ;
			break ;

			case self::BLOCK_DATA:

				if (!$this->_block instanceof block\data)
					$this->_block = block\data::factory($this->_stream) ;

				if (!$this->_block->parse())
					return false ;

				if ($this->_block->is_complited()) {
					$this->_complited = true ;
					$this->_state = self::STATE_COMPLITED ;
				}

				return true ;
			break ;

			default:

				return false ;
			break ;
		}

		if ($this->_state == self::STATE_COMPLITED)
			return true ;

		return false ;
    }

    public function compose($eof = false) {

		if ($this->_state == self::STATE_INIT) {
			$this->_offset = $this->_getpos() ;

			if ($this->_result_mode) {

				if (!$this->_result->compose())
					return false ;

				if (($this->_result->get_code() !== 0) || !in_array($this->_code, array(self::BLOCK_DATA, self::BLOCK_KEYGEN)))
					return true ;

			} else {

				if (is_null($this->_code))
					return false ;

				if (!$this->compose_header())
					return false ;
			}
		}

		switch($this->_code) {

			case self::BLOCK_CLOSE:

				if (!$this->compose_control($eof))
					return false ;

				return true ;
			break ;

			case self::BLOCK_KEEP_ALIVE:

				return true ;
			break ;

			case self::BLOCK_KEYGEN:
			case self::BLOCK_CRYPT:
			case self::BLOCK_DATA:

				if ($this->_state == self::STATE_INIT)
					$this->_state = self::STATE_DATA ;

				if ($this->_state == self::STATE_DATA)
					$this->_block->compose($eof) ;

				return true ;
			break ;

			default:

				return false ;
			break ;
		}

	}

	public function get_offset() {
		return $this->_offset ;
	}

	public function write_buffer($buf) {
		return $this->_block->write_buffer($buf) ;	}

	public function get_control() {

		return $this->_control ;
	}

	public function block() {

		return $this->_block ;
	}

	public function result() {

		return $this->_result ;
	}

	public static function factory(&$stream, $result_mode = NULL, $result = NULL) {

		return new self($stream, $result_mode, $result) ;
	}

}


namespace protocol ;

class bbdx extends \protocol\bbdx\stream implements ibbdx {
	protected $_init ;

	protected $_gzip ;

	protected $_routing ;

	protected $_format ;

	protected $_sign_type ;

	protected $_idle ;

	protected $_source_id ;

	protected $_block ;

	protected $_crypted ;

	private $_key ;

	private $_iv ;

	private $_td ;

	const DATA_INIT = 0x01 ;
	const DATA_PROCESS = 0x02 ;
	const DATA_COMPLITED = 0x04 ;

	public function __construct() {
		$this->_init = false ;
	}

	public function __destruct() {

		parent::__destruct() ;
	}

	public function crypt_init($key, $iv) {
		$this->_key = $key ;
		$this->_iv = $iv ;

	 	$this->_td = mcrypt_module_open('rijndael-128', '', 'cbc', '') ;
		mcrypt_generic_init($this->_td, $this->_key, $this->_iv) ;

		$this->_crypted = true ;
	}

	public function crypt_deinit() {

		mcrypt_generic_deinit($this->_td) ;
	 	mcrypt_module_close($this->_td) ;

		$this->_crypted = false ;
	}

	protected function _encrypt($data) {
		return mcrypt_generic($this->_td, $data) ;
	}

	protected function _decrypt($data) {

		return mdecrypt_generic($this->_td, $data) ;
	}

}

namespace protocol\bbdx ;

class request extends \protocol\bbdx implements \protocol\ibbdx {
	protected $_stream ;

	private $_response_mode ;

	private $_result ;

	private $_length ;

	public function __construct($response_mode = false) {
		$this->_stream = fopen("php://memory", "r+") ;

		$this->_response_mode = $response_mode ;
		$this->_result = NULL ;

		$this->_crypted = false ;

		parent::__construct($this->_stream) ;
	}

	public function __call($name, $args) {
		if (!in_array($name, array('gzip', 'format', 'sign_type', 'source_id', 'idle')))
			trigger_error('Call to undefined method '.__CLASS__.'::'.$name.'()', E_USER_ERROR) ;

		$val = '_'.$name ;
		if (property_exists($this, $val)) {

			if (isset($args[0]))
				$this->$val = $args[0] ;
			else return $this->$val ;
		}

		return $this ;
	}

	public function handshake() {
		$this->_block = \protocol\bbdx\handshake::factory($this->_stream, $this->_idle, $this->_source_id) ;
		$this->_block->compose(true) ;
		if ($this->_crypted)
			$this->_block->_padding_write() ;
        $this->_block = NULL ;

		return $this ;	}

	public function close($reason = NULL) {

		$this->_block = \protocol\bbdx\block::factory($this->_stream, $this->_response_mode, $this->_result)->close($reason) ;
		$this->_block->compose(true) ;
		if ($this->_crypted)
			$this->_block->_padding_write() ;
        $this->_block = NULL ;


		return $this ;
	}

	public function keep_alive() {

		$this->_block = \protocol\bbdx\block::factory($this->_stream, $this->_response_mode, $this->_result)->keep_alive() ;
		$this->_block->compose(true) ;
		if ($this->_crypted)
			$this->_block->_padding_write() ;
        $this->_block = NULL ;


		return $this ;
	}

	public function keygen($data) {

		$this->_block = \protocol\bbdx\block::factory($this->_stream, $this->_response_mode, $this->_result)->keygen($data) ;
		$this->_block->compose(true) ;
		if ($this->_crypted)
			$this->_block->_padding_write() ;
        $this->_block = NULL ;

		return $this ;
	}

	public function crypt($key_hash) {

		$this->_block = \protocol\bbdx\block::factory($this->_stream, $this->_response_mode, $this->_result)->crypt($key_hash) ;
		$this->_block->compose(true) ;
		if ($this->_crypted)
			$this->_block->_padding_write() ;
        $this->_block = NULL ;


		return $this ;
	}

	public function result($code, $close) {

		$this->_result = \protocol\bbdx\block\result::factory($this->_stream, $code, $close) ;

		return $this ;
	}

	private function _block_release() {

		if (!$this->_block instanceof block)			$this->_block = \protocol\bbdx\block::factory($this->_stream, $this->_response_mode, $this->_result) ;

		return $this->_block ;
	}

	public function data($buf) {

		$this->_length = strlen($buf) ;

		$this->_block_release() ;

		$this->_block->data(
				$this->_format, (
					($this->_gzip * 0xFF & self::FLAG_GZIP) |
					($this->_routing * 0xFF & self::FLAG_ROUTING)
				),
				$this->_length,
				$this->_sign_type
		) ;


		$this->_block->compose() ;

		$this->_block->write_buffer($buf) ;

		$this->_block->compose(true) ;

		if ($this->_crypted)
			$this->_block->_padding_write() ;

        $this->_block = NULL ;

		return $this ;
	}

	public function send() {
       /*
		if (!is_resource($this->stream_output))
			return false ;

		rewind($this->_stream) ;

		while(feof($this->_stream)) {
			fread($this->_stream, 16)


		}


    	return stream_get_contents($this->_stream) ;
    	*/
	}

	public function get() {

		rewind($this->_stream) ;


		$buf = NULL ;
		while(!feof($this->_stream)) {

			$data = fread($this->_stream, 16*256) ;

			if ($this->_crypted)
				$data = $this->_encrypt($data) ;

			$buf.= $data ;
		}

    	return $buf ;
	}

	public function flush() {		$this->_flush($this->_length()) ;
		//$this->_offset = 0 ;
		$this->_result = NULL ;
		return $this ;
	}

	public static function factory($response_mode = false) {

		return new self($response_mode) ;
	}

}


class trigger extends \trigger {

	const TRIGGER_INIT = 0x01 ;
    const TRIGGER_CLOSE = 0x02 ;
    const TRIGGER_KEEP_ALIVE = 0x03 ;
    const TRIGGER_DATA_INIT = 0x04 ;
    const TRIGGER_DATA_PROCESS = 0x05 ;
    const TRIGGER_DATA_COMPLETE = 0x06 ;
    const TRIGGER_KEYGEN = 0x07 ;
    const TRIGGER_CRYPT = 0x08 ;
    const TRIGGER_RESULT = 0x09 ;
    const TRIGGER_PARSING_ERROR = 0x0A ;

}


namespace protocol\bbdx ;

class response extends \protocol\bbdx implements \protocol\ibbdx {

	protected $_stream ;
	private $_trigger ;
//	private $_complited ;
	private $_offset ;

	private $_buffer ;

	private $td ;

	private $_response_mode ;
	private $_response_code ;

	private $_last_result ;

	const STREAM_PASS = 0x04 ;
	const STREAM_EOF = 0x08 ;
	const PARSE_ERROR = 0x10 ;

	public function __construct($response_mode = false) {

		$this->_stream = fopen("php://memory", "r+") ;

		$this->_offset = 0 ;

		$this->_buffer = NULL ;

		$this->_crypted = false ;

		$this->_response_mode = $response_mode ;
		$this->_response_code = NULL ;


		$this->_trigger = new trigger() ;
		parent::__construct($this->_stream) ;
	}

	public function handshake($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_INIT) ;

		return $this ;
	}

	public function close($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_CLOSE) ;

		return $this ;
	}

	public function keep_alive($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_KEEP_ALIVE) ;

		return $this ;
	}

	public function keygen($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_KEYGEN) ;

		return $this ;
	}

	public function crypt($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_CRYPT) ;

		return $this ;
	}

	public function result($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_RESULT) ;

		return $this ;
	}

	public function data($func) {

		$this->_trigger->hook($func, trigger::TRIGGER_DATA_PROCESS) ;
		$this->_trigger->hook($func, trigger::TRIGGER_DATA_INIT) ;
		$this->_trigger->hook($func, trigger::TRIGGER_DATA_COMPLETE) ;

		return $this ;
	}

	public function response($code) {
		$this->_response_code = $code ;

		return $this ;
	}

	private function _process() {

		$result = NULL ;

		if (($this->_offset >= $this->_stream_length) && (!$this->_block instanceof block || $this->_block->is_complited()))
			return self::STREAM_EOF ;

		if (!$this->_init)
			if ($this->_stream_length >= handshake::CHUNK_SIZE) {

				$handshake = handshake::factory($this->_stream) ;
				if (!$handshake->parse())
					return self::PARSE_ERROR ;

				$this->_init = true ;
				$this->_offset = $this->_getpos() ;

				if ($this->_crypted)
					$this->_offset = $handshake->_padding_skip() ;

				$arg = array($handshake->idle, $handshake->source_id) ;
				$this->_trigger->event(trigger::TRIGGER_INIT, $arg) ;

				return true ;
			} else return self::STREAM_PASS ;

		if ($this->_init) {

			if (!$this->_block instanceof block)
            	$this->_block = block::factory($this->_stream, $this->_response_mode) ;
				if ($this->_response_mode)
            		$this->_block->set_code($this->_response_code) ;

			if (($this->_stream_length - $this->_offset) >= (int)$this->_block->get_chunk_size()) {

	            if (!$this->_block->parse())
	            	return self::PARSE_ERROR ;
/*
				if ($this->_stream_length == $this->_offset)
					if ($this->_block->is_complited())
						return self::STREAM_EOF ;
					else
						return self::STREAM_PASS ;
*/
				$this->_offset = $this->_getpos() ;

				if ($this->_block->is_header()) {
					return true ;
				}

				if ($this->_response_mode)
						$result = $this->_block->result() ;

				$crypt_blocked = $this->_crypted ;

				switch($this->_block->get_code()) {

					case self::BLOCK_CLOSE:

						$control = $this->_block->get_control() ;
						$reason = is_array($control)?array_shift($control):0 ;
						$this->_trigger->event(trigger::TRIGGER_CLOSE, array(is_null($result)?$reason:NULL, $result)) ;
					break ;

					case self::BLOCK_KEEP_ALIVE:

						$this->_trigger->event(trigger::TRIGGER_KEEP_ALIVE, array($result)) ;
					break ;

					case self::BLOCK_KEYGEN:

						if ($this->_block->block()->is_complited())
							$this->_trigger->event(trigger::TRIGGER_KEYGEN, array($this->_block->block()->get_data(), $result)) ;
					break ;

					case self::BLOCK_CRYPT:

						$this->_trigger->event(trigger::TRIGGER_CRYPT, array(is_null($result)?$this->_block->block()->get_key_hash():NULL, $result)) ;
					break ;

					case self::BLOCK_DATA:

			            if ($this->_block->block()->is_header())
							$this->_trigger->event(trigger::TRIGGER_DATA_INIT, array(NULL, $this->_block->block()->get_format(), $this->_block->block()->get_flags(), self::DATA_INIT, $result)) ;

			            if ($this->_block->block()->is_data())
							$this->_trigger->event(trigger::TRIGGER_DATA_PROCESS, array($this->_block->block()->get_buffer(), $this->_block->block()->get_format(), $this->_block->block()->get_flags(), self::DATA_PROCESS, $result)) ;

			            if ($this->_block->block()->is_complited()) {

			            	$this->_offset = $this->_getpos() ;
							$this->_trigger->event(trigger::TRIGGER_DATA_COMPLETE, array($this->_block->block()->get_buffer(), $this->_block->block()->get_format(), $this->_block->block()->get_flags(), self::DATA_COMPLITED | self::DATA_PROCESS, $result)) ;
			            }

					break ;

					default:

						return self::PARSE_ERROR ;
					break ;

				}

			    if ($this->_block->is_complited()) {
					if ($this->_crypted && $crypt_blocked)
			    		$this->_offset = $this->_block->_padding_skip() ;

       				$this->_block = NULL ;

				} elseif ($this->_stream_length == $this->_offset)
					if (is_null($this->_block))
						return self::STREAM_EOF ;
					else
						return self::STREAM_PASS ;


			} else return self::STREAM_PASS ;

			return true ;
		}

		return false ;
	}

	public function parse() {
		fseek($this->_stream, $this->_offset) ;

		do {

			$status = $this->_process() ;

			if ($status === self::PARSE_ERROR) {

				$this->_trigger->event(trigger::TRIGGER_PARSING_ERROR, array(NULL)) ;
				return false ;
			}

		} while(!($status & (self::STREAM_PASS | self::STREAM_EOF))) ;

		$this->_last_result = $status ;

		if ($this->_flush($this->_offset))
			$this->_offset = 0 ;

		return true ;
	}

	public function read($buf) {
		//rewind($this->_stream) ;

		if ($this->_crypted)
			$buf = $this->_decrypt($buf) ;

//		$data = fread($this->_stream, 16) ;

		$this->_write($buf) ;
		return $this->parse() ;
	}

	public function eof() {

		return ($this->_last_result === self::STREAM_PASS) ;
	}

	public function get() {

    	return stream_get_contents($this->_stream) ;
	}

	public static function factory($response_mode = false) {

		return new self($response_mode) ;
	}

}

namespace protocol\bbdx ;

abstract class dispatcher implements \protocol\ibbdx {

	protected $_key ;
	protected $_rsa ;

	protected $_key_aes ;
	protected $_key_rsa ;

	protected $_callbacks ;

	protected $_crypted ;

	public function on_data($callback) {

		if (!is_callable($callback))
			return false ;

		$this->_callbacks['data'] = $callback ;

		return $this ;
	}

}

namespace protocol\bbdx ;

class client extends dispatcher implements \protocol\ibbdx {

	private $_request ;
	private $_response ;

	private $_tcp ;

	private $_init ;

	private $_request_type ;
	private $_last_result ;

	private $_data ;
	private $_idle ;
	private $_source_id ;

	public function __construct($ip, $port, $source_id, $crypted) {
		$this->_crypted = $crypted ;

		$this->_tcp = \net\tcp\client::factory($ip, $port) ;

		$this->_request = \protocol\bbdx\request::factory() ;

		$this->_request
			->format(\protocol\bbdx::DATA_TYPE_BSON)
			->gzip(false)
			->idle(3)
			->source_id(pack('H*', $source_id))
		;

		$this->_response = \protocol\bbdx\response::factory(true) ;

		$this->_last_result = NULL ;

		$this->_response
			->handshake(array($this, 'handshake'))
			->close(array($this, 'close'))
			->keep_alive(array($this, 'keep_alive'))
			->keygen(array($this, 'keygen'))
			->crypt(array($this, 'crypt'))
			->data(array($this, 'data'))
   		;
	}

	public function __destruct() {
		$this->_tcp->disconnect() ;
	}

	public function is_init() {
		return $this->_init ;
	}

	private function _response($length = NULL) {
		do {

			if (($buf = $this->_tcp->recv(true)) === false)
	    		return false ;

	    	if ($this->_response->read($buf) === false)
	    		return false ;

		} while($this->_response->eof()) ;

  		return true ;
	}

	private function _keygen($key_data) {

		$this->_response->response(self::BLOCK_KEYGEN) ;
		$data = $this->_request->flush()->keygen($key_data)->get() ;

		$this->_tcp->send($data) ;

		if (!$this->_response() || ($this->_last_result !== self::RESULT_SUCCESS))
				return false ;

		return true ;
	}

	private function _crypt($key_hash) {
		$this->_response->response(self::BLOCK_CRYPT) ;
		$data = $this->_request->flush()->crypt($key_hash)->get() ;

		$this->_tcp->send($data) ;

		if (!$this->_response() || ($this->_last_result !== self::RESULT_SUCCESS))
				return false ;

		return true ;
	}

	public function init() {
		$this->_response->response(self::BLOCK_HANDSHAKE) ;
		$data = $this->_request->flush()->handshake()->get() ;

		$this->_tcp->send($data) ;

		if (!$this->_response() || ($this->_last_result !== self::RESULT_SUCCESS))
				return false ;

		if ($this->_crypted) {
			$this->_key[0] = openssl_random_pseudo_bytes(8) ;

			$rsa = new \crypt\rsa(\config::get('dir.keys_rsa')) ;
			$this->_rsa[0] = $rsa->encrypt($this->_key[0], true) ;

			if (!$result = $this->_keygen($this->_rsa[0]))
				return false ;

			if (!$this->_key[1] = $rsa->decrypt($this->_rsa[1], false))
				return false ;

			$this->_key_rsa = $this->_rsa[1].$this->_rsa[0] ;
			$this->_key_aes = $this->_key[1].$this->_key[0] ;

			if (!$result = $this->_crypt(sha1($this->_key_rsa)))
				return false ;

			$this->_request->crypt_init($this->_key_aes, substr($this->_key_rsa, 0, 16)) ;
			$this->_response->crypt_init($this->_key_aes, substr($this->_key_rsa, 0, 16)) ;
		}

		$this->_init = true ;

		return true ;
	}

	public function request($data, $callback = NULL) {
		if (!$this->_tcp->is_connected())
			return false ;

		if (!$this->is_init())
			if (!$this->init())
				return false ;

		$this->_response->response(self::BLOCK_KEEP_ALIVE) ;

		$this->_tcp->send($this->_request->flush()->keep_alive()->get()) ;

		if (!$this->_response() || $this->_last_result !== self::RESULT_SUCCESS)
			return $this->_last_result ;


		$this->_response->response(self::BLOCK_DATA) ;
		$data = $this->_request->flush()->data($data)->get() ;

		$this->_tcp->send($data) ;

		if (!$this->_response() || $this->_last_result !== self::RESULT_SUCCESS)
			return $this->_last_result ;

		return true ;
	}

	public function finalize($reason = 0) {

		$this->_response->response(self::BLOCK_CLOSE) ;
		$data = $this->_request->flush()->close($reason)->get() ;

		$this->_tcp->send($data) ;

		if (!$this->_response() || $this->_last_result !== self::RESULT_SUCCESS)
			return false ;

		$this->_tcp->disconnect() ;

		return true ;
	}

	public function process() {
		if (!$this->_tcp->is_connected())
			return false ;

		$data = $this->_tcp->recv() ;

  		return $this->_response->read($buf) ;
	}

	public function destroy() {
    	$this->_tcp->disconnect() ;
    	return true ;
	}

	public function data($data, $format, $flags, $event, $result) {
		if ($this->_check_result($result)) {
			if ($event & \protocol\bbdx\response::DATA_INIT)
				$this->_data = NULL ;
			if ($event & \protocol\bbdx\response::DATA_PROCESS)
				$this->_data.= $data ;

				if (isset($this->_callbacks['data']))
					call_user_func($this->_callbacks['data'], $data,$format, $flags, $event) ;
		}

		$this->_last_result = $result->get_code() ;
	}

	public function handshake($idle, $source_id) {
		$this->_idle = $idle ;
		$this->_source = $source_id ;
		$this->_last_result = self::RESULT_SUCCESS ;
	}

	public function keygen($data, $result) {

		if ($this->_check_result($result))
			$this->_rsa[1] = $data ;

		$this->_last_result = $result->get_code() ;
	}

	public function crypt($data, $result) {

		$this->_last_result = $result->get_code() ;
	}

	public function keep_alive($result) {

		$this->_last_result = $result->get_code() ;
	}

	public function close($reason, $result) {

		$this->_last_result = $result->get_code() ;
	}

	private function _check_result($result) {
		if ($result->get_close())
			$this->finalize() ;

		return ($result->get_code() === self::RESULT_SUCCESS) ;
	}

}

namespace protocol\bbdx\server ;

class client extends \protocol\bbdx\dispatcher implements \protocol\ibbdx {

	private $_server ;
	private $_client ;
	private $_client_id ;

	private $_request ;
	private $_response ;

	private $_idle ;
	private $_source_id ;

	private $_closed ;

	private $_buffer ;

	const IDLE_MAX = 30 ;
	const IDLE_MIN = 3 ;

	public function __construct(&$server, $client_id, $source_id) {

		$this->_server = $server ;
		$this->_client_id = $client_id ;
		$this->_source_id = $source_id ;

		$this->_client = $this->_server->client($client_id) ;

		$this->_response = new \protocol\bbdx\response() ;

        $this->_response
        	->handshake(array($this, 'handshake'))
        	->close(array($this, 'close'))
        	->keep_alive(array($this, 'keep_alive'))
        	->keygen(array($this, 'keygen'))
        	->crypt(array($this, 'crypt'))
        	->data(array($this, 'data'))
  		;

		$this->_request = \protocol\bbdx\request::factory(true) ;

		$this->_idle = self::IDLE_MIN ;

		$this->_client->idle($this->_idle) ;

	}

	public function __destruct() {

		$this->_client->destroy() ;
	}

	public function process() {
		$buf = $this->_client->buffer ;

		if ($this->_response->read($buf) === false) {

			$this->_destroy(self::RESULT_PARSING_ERROR) ;
			return false ;
		}

		if ($this->_closed)
			return false ;

		return true ;
	}

	public function handshake($idle, $source_id) {

//		$this->_idle = ($idle > self::IDLE_MAX)?self::IDLE_MAX:($idle < self::IDLE_MIN)?self::IDLE_MIN:$idle ;

		$this->_idle = $idle ;

		$this->_client->idle($this->_idle) ;

		$data = $this->_request
				->flush()
				->source_id(pack('H*', $this->_source_id))
				->idle($this->_idle)
				->handshake()
				->get()
		;

		$this->_client->write($data) ;
	}

	public function close($reason) {

		$this->_destroy(self::RESULT_SUCCESS) ;
	}

	public function keep_alive() {

		$data = $this->_request
				->flush()
				->result(self::RESULT_SUCCESS, 0)
				->keep_alive()
				->get()
		;

		$this->_client->write($data) ;
	}

	public function keygen($data) {

		$this->_rsa[0] = $data ;
		$this->_key[1] = openssl_random_pseudo_bytes(8) ;

		$rsa = new \crypt\rsa(\config::get('dir.keys_rsa')) ;
		$this->_key[0] = $rsa->decrypt($data, false) ;

		if ($this->_key[0] === false) {
			$this->_destroy(self::RESULT_SIGN_ERROR) ;
			return false ;
		}

		$this->_rsa[1] = $rsa->encrypt($this->_key[1], true) ;

		$this->_key_rsa = $this->_rsa[1].$this->_rsa[0] ;
		$this->_key_aes = $this->_key[1].$this->_key[0] ;

		$data = $this->_request
				->flush()
				->result(self::RESULT_SUCCESS, 0)
				->keygen($this->_rsa[1])
				->get()
		;

		$this->_client->write($data) ;
	}

	public function crypt($key_hash) {

		$data = $this->_request
				->flush()
				->result(self::RESULT_SUCCESS, 0)
				->crypt($key_hash)
				->get()
		;

		$this->_request->crypt_init($this->_key_aes, substr($this->_key_rsa, 0, 16)) ;
		$this->_response->crypt_init($this->_key_aes, substr($this->_key_rsa, 0, 16)) ;

		$this->_client->write($data) ;
	}

	public function data($data, $format, $flags, $event) {

		$response = '' ;
		$resource = NULL ;

		if (isset($this->_callbacks['data']))
			$resource = call_user_func($this->_callbacks['data'], $data, $format, $flags, $this->_client_id, $event) ;

		if ($event & \protocol\bbdx\response::DATA_COMPLITED) {

			if ($resource instanceof \protocol\bbdx\resource && ($resource->code == true))
				$response = $resource->get() ;

			$data = $this->_request
					->flush()
					->format($resource->format)
					->result(self::RESULT_SUCCESS, 0)
					->data($response)
					->get()
			;

			$this->_client->write($data) ;
		}

	}

	private function _destroy($code) {
		$data = $this->_request
				->flush()
				->result($code, 1)
				->close(0)
				->get()
		;

		$this->_client->write($data) ;
	}

}


namespace protocol\bbdx ;

class resource extends stream {
	protected $_stream ;
	public $code ;
	public $format ;

	public function __construct($code = NULL, $data = NULL, $format = NULL) {
		$this->code = $code ;
		$this->format = $format ;

		$this->_stream = fopen("php://memory", "r+") ;

		parent::__construct($this->_stream) ;

		if (!is_null($data))
			$this->write($data) ;
	}

	public function __destruct() {
		fclose($this->_stream) ;
	}

	public function __toString() {

		return $this->get() ;
	}

	public function write($buf) {
		$this->_write($buf) ;
	}

	public function get() {

		rewind($this->_stream) ;
		return stream_get_contents($this->_stream) ;
	}

	public function get_stream() {

		return $this->_stream ;
	}

	public static function factory($code = NULL, $data = NULL, $format = NULL) {
		return new self($code, $data, $format) ;
	}

}

namespace protocol\bbdx ;

class server extends dispatcher implements \protocol\ibbdx {

	private $_tcp ;

	private $_source_id ;

	private $_streams ;

	const IDLE_MAX = 30 ;
	const IDLE_MIN = 3 ;

	public function __construct($ip, $port, $source_id, $crypted) {

		$this->_crypted = $crypted ;
		$this->_source_id = $source_id ;

		try {

			$this->_tcp = new \net\tcp\server($ip, $port) ;

		} catch(Exception $e) {

			die($e->getMessage()) ;
		}

		$this->_tcp->hook(array($this, 'connect'), \net\tcp\server::TRIGGER_CONNECT) ;
		$this->_tcp->hook(array($this, 'data'), \net\tcp\server::TRIGGER_DATA) ;
		$this->_tcp->hook(array($this, 'disconnect'), \net\tcp\server::TRIGGER_DISCONNECT) ;
		$this->_tcp->hook(array($this, 'timeout'), \net\tcp\server::TRIGGER_TIMEOUT) ;
	}

	public function __destruct() {

		$this->_tcp->destroy() ;
	}

	public function on_data($callback) {

		if (!is_callable($callback))
			return false ;

		$this->_callbacks['data'] = $callback ;

		return $this ;
	}

	public function infinitie() {
		$this->_tcp->infinitie() ;
	}

	public function connect(&$client) {

   		$this->_streams[$client->id] = new server\client($this->_tcp, $client->id, $this->_source_id) ;
		if (isset($this->_callbacks['data']))
   			$this->_streams[$client->id]->on_data($this->_callbacks['data']) ;
	}

	public function data(&$client) {

		if (!$this->_streams[$client->id]->process())
			$client->destroy() ;
		else
			$client->buffer_flush() ;
	}

	public function disconnect(&$client) {

		//$this->_streams[$client->id]->disconnect() ;
		unset($this->_streams[$client->id]) ;
	}

	public function timeout(&$client) {

		//$this->_streams[$client->id]->timeout() ;
	}

}
