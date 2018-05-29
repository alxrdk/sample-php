<?php

namespace protocol ;

	class smg {

		const SIGNATURE = 'SMG' ;

		public $header = NULL ;

		private $len ;
		public $buf ;

		private $stream ;

		private $rsa ;


		public function __construct($rsa_keys_dir, &$stream = NULL) {
			$this->rsa = new \crypt\rsa($rsa_keys_dir) ;

			if (!is_null($stream))
				$this->attach_stream($stream) ;

		}

		private function attach_stream(&$stream) {

			if ($stream && is_resource($stream)) {
				$this->stream = $stream ;
				return true ;
			}
			return false ;
		}

		private function attach_data($data) {

			$stream = &$this->stream ;

			$stream = fopen("php://memory", "r+") ;
			fwrite($stream, $data) ;
			rewind($stream) ;

			return true ;
		}

		private function pack_arr($data) {
			return msgpack_pack($data) ;
		}

		private function unpack_arr($data) {

			return msgpack_unpack($data) ;
		}

		private function check_header($data) {
			$headers = array('len', 'sign', 'gzip', 'crc', 'raw', 'source_id', 'source_type') ;

			$arr = array_intersect_key($data, array_flip($headers)) ;

			$this->header = $arr ;
		}

		private function parse_header() {
			$buf = fread($this->stream, strlen(self::SIGNATURE)) ;

			if ($buf != self::SIGNATURE)
				return false ;

			if (($buf = fread($this->stream, 4)) === false)
				return false ;
			$crc = unpack('L', $buf) ;

			if (($buf = fread($this->stream, 4)) === false)
				return false ;
			$header_len = unpack('L', $buf) ;

			if (crc32($header_len[1]) != $crc[1])
				return false ;

			if (($buf_header = fread($this->stream, $header_len[1])) === false)
				return false ;

			$header = $this->unpack_arr($buf_header) ;

			if (empty($header)||(!is_array($header)))
				return false ;

    		$this->check_header($header) ;

			return true ;
		}

		public function verify($public = false) {
			return $this->rsa->verify($this->buf, $this->header['sign'], $public) ;
		}

		private function sign($public = false) {

			return $this->rsa->sign($this->buf, $public) ;
		}

		private function parse_body() {

			$header = &$this->header ;
			$buf = &$this->buf ;

			$buf_header = fread($this->stream, $header['len']) ;

			if (isset($header['crc'])) {				$crc = $header['crc'] ;

				if ($crc != crc32($buf_header))
					return false ;
			}

			if (isset($header['gzip']) && $header['gzip']) {				$buf_header = gzuncompress($buf_header) ;
			}

			$buf = $buf_header ;

			return true ;
		}

		private function compose_header() {

			$buf = self::SIGNATURE ;

			$header_pack = $this->pack_arr($this->header) ;
			$header_len = strlen($header_pack) ;
			$header_crc = crc32($header_len) ;

			$buf.= pack('L', $header_crc).pack('L', $header_len) ;

			$buf.= $header_pack ;

   			$this->header = $buf ;

			return true ;
		}

		private function compose_body() {

			$buf = &$this->buf ;
			$buf = $this->header.$buf ;

			return true ;
		}

		public function parse($data = NULL) {

			if (!is_null($data))
				$this->attach_data($data) ;

			if (!$this->parse_header())
				return false ;

			if ($this->parse_body())
				return $this->buf ;

			return false ;
		}

		public function compose($data, $gzip = false, $raw = false) {

			if ($gzip) {
				$data = gzcompress($data) ;			}

			$this->buf = $data ;

			$sign = $this->sign() ;

			$this->header = array(
					'len' => strlen($this->buf),
					'sign' => $sign,
					'gzip' => $gzip,
					'crc' => crc32($this->buf),
					'raw' => $raw
			) ;

			if (!$this->compose_header())
				return false ;

			if ($this->compose_body())
				return $this->buf ;

			return false ;
		}

		public function compose_request($data, $gzip = false, $source_id, $source_type) {

			if ($gzip) {
				$data = gzcompress($data) ;
			}

			$this->buf = $data ;

			$sign = $this->sign(false) ;

			$this->header = array(
					'len' => strlen($this->buf),
					'sign' => $sign,
					'gzip' => $gzip,
					'crc' => crc32($this->buf),
					'source_id' => $source_id,
					'source_type' => $source_type
			) ;

			if (!$this->compose_header())
				return false ;

			if ($this->compose_body())
				return $this->buf ;

			return false ;
		}

	}

?>