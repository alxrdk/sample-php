<?php

interface socket_defaults {

	const RECV_TIMEOUT = 5 ;
	const SEND_TIMEOUT = 5 ;

}

abstract class socket_trigger {
	const TRIGGER_DATA = 0x1 ;

	const TRIGGER_CONNECT = 0x2 ;

	const TRIGGER_DISCONNECT = 0x3 ;

	private $hooks = array() ;


	public function hook($function, $trigger) {

		if (!isset($this->hooks[$trigger])) $this->hooks[$trigger] = array() ;
		if (array_search($function, $this->hooks[$trigger]) === false) {
			$this->hooks[$trigger][] = $function ;
			return true ;
		}

		return false ;
	}

	public function unhook($function, $trigger = NULL) {

		if (!is_null($trigger)) {
			if ($ni = array_search($function, $this->hooks[$trigger]) != false)
				unset($this->hooks[$trigger][$ni]) ;
			return true ;
		} else {
			foreach($this->hooks as $trigger->$hooks) {
				if ($ni = array_search($function, $this->hooks[$trigger]) != false)
					unset($this->hooks[$trigger][$ni]) ;
				return true ;
			}
		}

		return false ;
	}

	public function trigger_hooks($trigger, &$client) {

		if (isset($this->hooks[$trigger])) {			foreach($this->hooks[$trigger] as $function) {
				if (call_user_func($function, $client) === false)
					break ;
			}
		}

	}

}

class socket_server extends socket_trigger implements socket_defaults {
	private $socket ;

	private $bind_ip ;

	private $port ;

	private $max_clients ;

	private $clients = array() ;

	public function __construct($bind_ip, $port, $max_clients = 1024) {

		$this->bind_ip = $bind_ip ;
		$this->port = $port ;
		$this->max_clients = $max_clients ;

		$this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) ;

		socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1) ;
		socket_set_nonblock($this->socket) ;

		if ($this->socket === false) {
			throw new Exception('socket_create failed: '.socket_strerror(socket_last_error())) ;
		}

		if (socket_bind($this->socket, $this->bind_ip, $port) === false) {
			throw new Exception('socket_bind failed: '.socket_strerror(socket_last_error())) ;
		}

		if (socket_listen($this->socket, SOMAXCONN) === false) {
			throw new Exception('socket_listen failed: '.socket_strerror(socket_last_error())) ;
		}

		return true ;
	}

	public function __destruct() {
		$this->destroy() ;
	}

	protected function destroy() {
		foreach($this->clients as $client) {
				socket_close($client->socket) ;
		}
		socket_close($this->socket) ;
	}

	public function process() {
		$i = 0 ;
		$read[$i] = $this->socket ;
		foreach($this->clients as $key=>$client) {
			if (($client->last_recv < time() - self::RECV_TIMEOUT) && ($client->last_send < time() - self::SEND_TIMEOUT)) {
				$client->destroy() ;
				unset($this->clients[$key]) ;
				unset($client) ;
				continue ;
			}

			if (isset($client) && isset($client->socket))				$read[$i++] = $client->socket ;
			else unset($this->clients[$key]) ;
		}


		$write = NULL ;
		$except = NULL ;
 		if (socket_select($read, $write, $except, 0, 100) < 1)
 			return false ;
			if (in_array($this->socket, $read)) {				if (sizeof($this->clients) <= $this->max_clients) {					$client_id = uniqid(sizeof($this->clients), true) ;
					$this->clients[$client_id] = new socket_server_client($this->socket, $client_id, $this) ;
					$this->trigger_hooks(self::TRIGGER_CONNECT, $this->clients[$client_id]) ;

				} else {                   	socket_close(socket_accept($this->socket)) ;
				}

				$key = array_search($this->socket, $read) ;
                unset($read[$key]) ;

			}

			foreach($this->clients as $client) {

				if (isset($client->socket) && in_array($client->socket, $read)) {
					$buffer = @socket_read($client->socket, 1024, PHP_BINARY_READ) ;

					$key = array_search($client->socket, $read) ;
	                unset($read[$key]) ;

					if ($buffer === false || $buffer == "") {						$client->destroy() ;					} else {
						$client->buffer_write($buffer) ;
						$this->trigger_hooks(self::TRIGGER_DATA, $client) ;
					}


				}

			}



	}

	public function infinitie() {
		while(true) { $this->process() ; usleep(666) ;}
	}

}

class socket_server_client implements socket_defaults {

	public $socket ;

	public $ip ;

	public $port ;

	public $hostname ;

	public $buffer = NULL ;

	public $id ;

	public $last_recv ;
	public $last_send ;

	private $parent ;

	public function __construct(&$server_socket, $client_id, &$parent) {

		$this->last_recv = time() ;
		$this->last_send = time() ;

		$this->id = $client_id ;
		$this->parent = $parent ;

		$this->socket = socket_accept($server_socket) ;
		socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, array("sec" => $this::RECV_TIMEOUT, "usec" => 0)) ;
		socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, array("sec" => $this::SEND_TIMEOUT, "usec" => 0)) ;
		socket_set_nonblock($this->socket) ;

		if ($this->socket) {
			socket_getpeername($this->socket, $this->ip, $this->port) ;
			logger::instance()->add(logger::DEBUG, 1, sprintf("tcp server: connect %s:%s", $this->ip, $this->port), logger::OW_GATEWAY) ;
		} else throw new Exception('socket error: '.socket_strerror(socket_last_error())) ;

	}

	public function lookup_hostname(&$server_socket) {
		return $this->hostname = gethostbyaddr($this->ip) ;
	}

	public function buffer_write($buffer) {
		$this->last_recv = time() ;

		$this->buffer.= $buffer ;
		logger::instance()->add(logger::DEBUG, 1, sprintf("tcp server: read %d bytes", strlen($buffer)), logger::OW_GATEWAY) ;
		return true ;
	}

	public function buffer_flush() {
		$this->buffer = NULL ;
	}

	public function write($buffer) {
		$this->last_send = time() ;

		$total = strlen($buffer) ;
		$written = 0 ;

		while($written < $total)			$written+= socket_write($this->socket, substr($buffer, $written)) ;
		logger::instance()->add(logger::DEBUG, 1, sprintf("tcp server: write %d bytes", $total), logger::OW_GATEWAY) ;
		return true ;
	}

	public function close() {

		if (isset($this->socket)) {
			socket_close($this->socket) ;
			unset($this->socket) ;
			return true ;
		}

		return false ;
	}

	public function destroy() {//		$this->__destruct() ;

		$this->close() ;
		unset($this) ;
	}

	public function __destruct() {
		$this->buffer_flush() ;
		unset($this->buffer) ;

		$this->close() ;

		$this->parent->trigger_hooks(socket_trigger::TRIGGER_DISCONNECT, $this) ;
		logger::instance()->add(logger::DEBUG, 1, sprintf("tcp server: disconnect %s:%s", $this->ip, $this->port), logger::OW_GATEWAY) ;
	}


}





?>