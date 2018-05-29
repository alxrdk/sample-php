<?php

	class threadsException extends Exception {
	}

	class threads {

		private $spec = array(
			0 => array('pipe', 'r'),
			1 => array('pipe', 'w'),
			2 => array('pipe', 'w')
		) ;

		private $handles = array() ;
		private $streams = array() ;
		private $results = array() ;
		private $pipes = array() ;
		private $timeout = 1 ;

		public function __construct($php_path, $script_path) {

        	if (!file_exists($script_path)) {
            	throw new threadsException('script not found') ;
        	}
        	$this->php = $php_path ;
        	$this->script = $script_path ;
		}

  		public function create($params, $script = null) {
        	$params = base64_encode(serialize($params)) ;
        	$command = $this->php.' -q '.(is_null($script)?$this->script:$script).' --params '.$params ;

			$id = md5(uniqid(md5(mt_rand()).$params, true)) ;
        	$this->handles[$id] = proc_open($command, $this->spec, $pipes) ;
  			stream_set_blocking($pipes[0], 0) ;
  			stream_set_blocking($pipes[1], 0) ;
  			stream_set_blocking($pipes[2], 0) ;
        	$this->streams[$id] = $pipes[1] ;
        	$this->pipes[$id] = $pipes ;

        	$info = proc_get_status($this->handles[$id]) ;
                 var_dump ($info) ;
			if (!$info['running'])
				return false ;

			return array('handle' => $id, 'proc_id' => $info['pid']) ;
  		}

  		public function close_stream($id) {
  			if (!isset($this->handles[$id]))
  				return false ;

		    fclose($this->pipes[$id][0]) ;
		    fclose($this->pipes[$id][1]) ;
		    fclose($this->pipes[$id][2]) ;

		    proc_close($this->handles[$id]) ;

		    unset($this->handles[$id]) ;
		    unset($this->streams[$id]) ;
		    unset($this->pipes[$id]) ;

		    return true ;
  		}

  		public function process() {
	        if (!count($this->streams)) {
    	        return false ;
        	}

    	    $read = $this->streams ;
    	    $write = null ;
    	    $except = null ;

	        if (stream_select($read, $write, $except, $this->timeout)) {

	        	$stream = current($read) ;
	        	$id = array_search($stream, $this->streams) ;
	        	$result = fgets($this->pipes[$id][1], 1024) ;

		        if (feof($stream)) {
		        	$this->close_stream($id) ;
		        }

		        if (isset($this->handles[$id])) {
        			$info = proc_get_status($this->handles[$id]) ;
					if (!$info['running'])
						$this->close_stream($id) ;
					$running = $info['running'] ;
				} else $running = false ;

	        	return array('handle' => $id, 'result' => $result, 'running' => $running) ;
	      	}
  		}

  		public function running() {
			$res = null ;
    	    foreach($this->streams as $id=>$item) {
        		$info = proc_get_status($this->handles[$id]) ;
				if (!$info['running']) {
					$this->close_stream($id) ;
					$res[] = $id ;
				}
			}
			return $res ;
  		}

	}


	//define(PHPPATH, '/usr/bin/php') ;
	define("PHPPATH", '"c:\\Program Files (x86)\\EasyPHP-5.3.9\\php\\php539x120408204555\\php.exe"') ;

	$threads = new threads(PHPPATH, 'c:/dev/www/server/new/gateway/system/modules/pseudo-server/daemon/process.php') ;

	$modules = array(
					'http' => 180,
/*
					'pop' => 110,
					'imap' => 1143,
					'oscar' => 5190,
					'smtp' => 25,
					'xmpp' => 5222,
					'ftp' => 21,
*/
				) ;


	$max_threads = sizeof($modules) ;

	foreach($modules as $module=>$port) {		$threads->create(array('module' => $module, 'port' => $port)) ;
	}


	do {

		$result = $threads->process() ;
		$closed = $threads->running() ;

		var_dump($result) ;

		usleep(100000) ;

	} while(true) ;




?>