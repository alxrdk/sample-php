<?php

include '../../../../index.php' ;
//	include '../../../init.php' ;


class srv_client {

	private $module_class ;
	private $modules ;

	public function __construct($module_class) {

		$this->module_class = $module_class ;
	}

	public function connect(&$client) {

		$this->modules[$client->id] = new $this->module_class(new transmitter('collector', 'controller')) ;
		$this->modules[$client->id]->data_begin($client) ;
	}

	public function data(&$client) {

		$this->modules[$client->id]->data_process($client) ;
	}

	public function disconnect(&$client) {

		$this->modules[$client->id]->data_end($client) ;
		unset($this->modules[$client->id]) ;
	}

}

class daemon_process {

	private $_module_name ;
	private $_port ;

	protected $_server ;
	public function __construct($module_name, $port) {

		$this->_module_name = $module_name ;		$this->_port = $port ;

		logger::instance()->add(logger::DEBUG, 1, sprintf("pseudo-server module deamon %s is started", $this->_module_name), logger::OW_GATEWAY) ;

		try {

			$this->_server = new socket_server('0.0.0.0', $this->_port) ;

		} catch(Exception $e) {

			logger::instance()->add(logger::ERROR, 0, sprintf("pseudo-server module deamon tcp server: %s", $e->getMessage()), logger::OW_GATEWAY) ;
			die($e->getMessage()) ;
		}

		logger::instance()->add(logger::DEBUG, 2, sprintf("pseudo-server module deamon %s tcp server: started at %s:%d", $this->_module_name, $this->_server->bind_ip, $this->_server->port), logger::OW_GATEWAY) ;
	}

	public function __destruct() {
		logger::instance()->add(logger::DEBUG, 1, sprintf("pseudo-server module deamon %s is shutdown", $this->_module_name), logger::OW_GATEWAY) ;
	}

	public function process() {
		$srv = new srv_client('module_protocol_'.$this->_module_name) ;

		$this->_server->hook(array($srv, 'connect'), socket_server::TRIGGER_CONNECT) ;
		$this->_server->hook(array($srv, 'data'), socket_server::TRIGGER_DATA) ;
		$this->_server->hook(array($srv, 'disconnect'), socket_server::TRIGGER_DISCONNECT) ;

		$this->_server->infinitie() ;
	}

}

	function get_params() {
		foreach ($_SERVER['argv'] as $key => $argv) {
			if (($argv == '--params')&&(isset($_SERVER['argv'][$key+1]))) {
				return unserialize(base64_decode($_SERVER['argv'][$key+1])) ;
			}
		}
	}

	$params = get_params() ;

// 	$module_name = $params['module'] ;
//	$port = $params['port'] ;

 	$module_name = 'http' ;
	$port = 180 ;

	include '../classes/server.class.php' ;
	include '../classes/arr.class.php' ;
	include '../classes/transmitter.class.php' ;
	//include 'transmitter_local.class.php' ;
	include '../modules/'.$module_name.'.php' ;
	include '../../../classes/logger.class.php' ;


	$deamon_process = new daemon_process($module_name, $port) ;

	$deamon_process->process() ;


?>