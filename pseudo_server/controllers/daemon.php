<?php

namespace modules\pseudo_server\controllers ;

class daemon {
	public function run($opts) {
		if (!isset($opts))
			return false ;

		$modules = $opts ;

		$threads = new \daemon\threads(\config::get('php_path')) ;

		$max_threads = sizeof($modules) ;

		foreach($modules as $module=>$port) {

			$threads->create('\modules\pseudo_server', array('daemon', 'process'), array('module' => $module, 'port' => $port)) ;
		}

		do {

			$result = $threads->process() ;
			$closed = $threads->running() ;

			usleep(100000) ;

		} while(true) ;

	}

	public function process($args) {

		$module_name = $args['module'] ;
		$port = $args['port'] ;
		$deamon = \modules\pseudo_server::model('process', array($module_name, $port)) ;

		$deamon->process() ;
	}


}