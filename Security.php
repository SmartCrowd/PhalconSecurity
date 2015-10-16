<?php
namespace SmartCrowd\Phalcon;

use \Phalcon\Acl;
use \Phalcon\Mvc\User\Plugin;

/**
 * Security
 * This is the security plugin which controls that users only have access to the modules they're assigned to
 */
abstract class Security extends Plugin
{
    public $acl;
    public $default_action;

    /**
     * Ex implementation: function getResources() { return $this->generateResources('/app/controllers/'); }
     * @return array Ex: [ [index] => [ 'index', 'notFound', 'route404', '*' ], ... ]
     */
    abstract function getResources();

    /**
     * @return array
     * Ex: [ 'guest' => [], 'admin' => ['guest'] ]
     */
    abstract function getRoles();

    /**
     * @return array
     * Ex: [ 'guest' => [ 'login' => ['*'] ], 'admin' => [ '*' => ['*'] ] ]
     */
    abstract function getAllowedResources();

    /**
     * @return array
     * Ex: [ 'guest' => [ 'shop' => ['*'] ], 'admin' => [ 'login' => ['*'] ] ]
     */
    abstract function getDeniedResources();

    /**
     * Function must return active user role for beforeDispatch event
     * @return string
     */
    abstract function getActiveRole();

    /**
     * Ex: function onAllowedAccess() { return true; }
     * @param $role
     * @param $controller
     * @param $action
     * @return bool
     */
    abstract function onAllowedAccess($role, $controller, $action);

    /**
     * Ex: function onDeniedAccess() { return false; }
     * @param $role
     * @param $controller
     * @param $action
     * @return bool
     */
    abstract function onDeniedAccess($role, $controller, $action);

    public function __construct($di, $default_action = Acl::DENY)
    {
        $this->setDI($di);
        $this->default_action = $default_action;
        $this->acl = $this->generateAcl();
    }

    public function generateAcl()
    {
        $acl = new Acl\Adapter\Memory();
        $acl->setDefaultAction($this->default_action);
        $this->registerRoles($acl);
        $this->addResources($acl);
        $this->registerResources($acl, $this->getAllowedResources(), Acl::ALLOW);
        $this->registerResources($acl, $this->getDeniedResources(), Acl::DENY);
        return $acl;
    }

    /**
     * @return \Phalcon\Acl\Adapter\Memory()
     */
    public function getAcl()
    {
        return $this->acl;
    }

    /**
     * Returns human readable rights map for role
     * @param $role
     * @return array
     */
    public function getAccessMap($role)
    {
        $acl = $this->getAcl();
        $resources = $this->getResources();
        $map = [];
        foreach ($resources as $controller => $actions) {
            foreach ($actions as $action) {
                $allowed = $acl->isAllowed($role, $controller, $action);
                $map[$controller][$action] = (int)$allowed;
            }
        }
        return $map;
    }

    public function isAllowed($role, $controller, $action)
    {
        $acl = $this->getAcl();
        return $acl->isAllowed($role, lcfirst($controller), lcfirst($action));
    }

    /**
     * Executed before execute any action in the application
     * @return bool
     */
    public function beforeDispatch()
    {
        $controller = $this->dispatcher->getControllerName();
        $action = $this->dispatcher->getActionName();
        $role = $this->getActiveRole();
        return ($this->isAllowed($role, $controller, $action)) ? $this->onAllowedAccess($role, $controller,
            $action) : $this->onDeniedAccess($role, $controller, $action);
    }

    /**
     * Automatic generated ACL resource list for all Controller classes in path
     * @param string $path
     * @return array
     */
    protected function generateResources($path)
    {
        if (file_exists($path)) {
            $files = scandir($path);
            foreach ($files as $file) {
                if (!preg_match('/.php$/', $file)) {
                    continue;
                }
                include_once($path . $file);
            }
        }
        $resources = [];
        $classes = get_declared_classes();
        foreach ($classes as $class) {
            if (!stristr($class, 'Controller')) {
                continue;
            }
            $methods = get_class_methods($class);
            $resourceMethods = [];
            foreach ($methods as $method) {
                if (preg_match('/Action$/', $method) > 0) {
                    $resourceMethods[] = lcfirst(preg_replace("/Action$/", "", $method));
                }
            }
            if (!empty($resourceMethods)) {
                $resourceMethods[] = '*';
            }
            $className = join('', array_slice(explode('\\', $class), -1));
            $resourceClassName = lcfirst(str_replace('Controller', '', $className));
            if (!empty($resourceClassName) && !empty($resourceMethods)) {
                $resources[$resourceClassName] = $resourceMethods;
            }
        }
        return $resources;
    }

    /**
     * @param $acl \Phalcon\Acl\Adapter\Memory()
     */
    protected function registerRoles($acl)
    {
        $roles = $this->getRoles();
        foreach ($roles as $role => $inherits) {
            $role = new Acl\Role($role);
            $acl->addRole($role);
        }
        foreach ($roles as $role => $inherits) {
            foreach ($inherits as $child) {
                $acl->addInherit($role, $child);
            }
        }
    }

    /**
     * @param $acl \Phalcon\Acl\Adapter\Memory()
     */
    protected function addResources($acl)
    {
        $resources = $this->getResources();
        foreach ($resources as $resource => $actions) {
            $acl->addResource(new Acl\Resource($resource), $actions);
        }
    }

    /**
     * @param $acl  \Phalcon\Acl\Adapter\Memory()
     * @param array $resources
     * @param bool $type
     */
    protected function registerResources($acl, $resources, $type)
    {
        foreach ($resources as $role => $resource) {
            foreach ($resource as $class => $actions) {
                foreach ($actions as $action) {
                    $type ? $acl->allow($role, $class, $action) : $acl->deny($role, $class, $action);
                }
            }
        }
    }
}