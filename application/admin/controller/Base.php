<?php
namespace app\admin\controller;
use think\Controller;
use think\Session;
use think\Url;
use think\Db;
class Base extends Controller
{
    /**
     * 析构函数
     */
    function __construct()
    {
        Session::start();
        parent::__construct();
	}

    /*
     * 初始化操作
     */
    public function _initialize()
    {
        //过滤不需要登陆的行为
        if(in_array(ACTION_NAME,array('login','logout','vertify'))){
        	//return;
        }else{
        	if(session('admin_id') > 0){
        		$this->check_priv();//检查管理员菜单操作权限
        	}else{
        		$this->error('请先登录',url('Admin/Systems.Admin/login'),1);
        	}
        }
        $this->public_assign();
    }
	
    /**
     * 保存公告变量到 smarty中 比如 导航
     */
    public function public_assign()
    {
       $tpshop_config = array();
       $tp_config = Db::table(PREFIX.'config')->cache(true)->select();
       foreach($tp_config as $k => $v)
       {
          $tpshop_config[$v['inc_type'].'_'.$v['name']] = $v['value'];
       }
       $this->assign('tpshop_config', $tpshop_config);
    }
	
    public function check_priv()
    {
    	$ctl = CONTROLLER_NAME;
    	$act = ACTION_NAME;
        $act_list = session('act_list');
		//无需验证的操作
		$uneed_check = array('login','suppliers_login','logout','vertifyHandle','vertify','imageUp','upload','login_task','ueditor');
    	if($ctl == 'Index' || $act_list == 'all'){
    		//后台首页控制器无需验证,超级管理员无需验证
    		return true;
    	}elseif(request()->isAjax() || strpos($act,'ajax')!== false || in_array($act,$uneed_check)){
    		//所有ajax请求不需要验证权限
    		return true;
    	}else{
    		$right = M('system_menu')->where("id", "in", $act_list)->cache(true)->getField('right',true);
    		foreach ($right as $val){
    			$role_right .= $val.',';
    		}
    		$role_right = explode(',', $role_right);
    		//检查是否拥有此操作权限
    		if(!in_array($ctl.'@'.$act, $role_right)){
    			$this->error('您没有操作权限['.($ctl.'@'.$act).'],请联系超级管理员分配权限',U('Admin/Index/welcome'));
    		}


    	}
    }

    public function ajaxReturn($data,$type = 'json'){
            exit(json_encode($data));
    }
}
