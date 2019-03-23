<?php
namespace app\admin\controller\Systems;

use think\Page;
use app\admin\controller\Base;
use think\Verify;
use think\Db;
use think\Session;
use think\Url;

class Admin extends Base
{

    public function index()
    {
        $list = array();
        $keywords = trim($this->request->post('keywords'));
        if (empty($keywords)) {
            $res = DB::name('admin')->select();
        } else {
            $res = DB::name('admin')->where('user_name', 'like', '%' . $keywords . '%')->order('admin_id')->select();
        }
        $role = DB::name('admin_role')->getField('role_id,role_name');
        if ($res && $role) {
            foreach ($res as $val) {
                $val['role'] = $role[$val['role_id']];
                $val['add_time'] = date('Y-m-d H:i:s', $val['add_time']);
                $list[] = $val;
            }
        }
        $this->assign('list', $list);
        return $this->fetch();
    }

    /**
     * 修改管理员密码
     * @return \think\mixed
     */
    public function modify_pwd()
    {
        $admin_id = intval($this->request->post('admin_id'));
        $oldPwd = trim($this->request->post('old_pw'));
        $newPwd = trim($this->request->post('new_pw'));
        $new2Pwd = trim($this->request->post('new_pw2'));

        if ($admin_id) {
            $info = Db::table('admin')->where("admin_id", $admin_id)->find();
            $info['password'] = "";
            $this->assign('info', $info);
        }

        if (IS_POST) {
            //修改密码
            $enOldPwd = encrypt($oldPwd);
            $enNewPwd = encrypt($newPwd);
            //TODO zjm 2018-6-14 当前存在门店登录则修改门店账号密码
            if(session('suppliers_id')){
                $suppliers = Db::table('suppliers')->where('suppliers_id', session('suppliers_id'))->find();
                if (!$suppliers || $suppliers['password'] != $enOldPwd) {
                    exit(json_encode(array('status' => -1, 'msg' => '旧密码不正确')));
                } else if ($newPwd != $new2Pwd) {
                    exit(json_encode(array('status' => -1, 'msg' => '两次密码不一致')));
                } else {
                    $row =  Db::table('suppliers')->where('suppliers_id', session('suppliers_id'))->save(array('password' => $enNewPwd));
                    if ($row) {
                        exit(json_encode(array('status' => 1, 'msg' => '修改成功')));
                    } else {
                        exit(json_encode(array('status' => -1, 'msg' => '修改失败')));
                    }
                }
            }else{
                $admin =  Db::table('admin')->where('admin_id', $admin_id)->find();
                if (!$admin || $admin['password'] != $enOldPwd) {
                    exit(json_encode(array('status' => -1, 'msg' => '旧密码不正确')));
                } else if ($newPwd != $new2Pwd) {
                    exit(json_encode(array('status' => -1, 'msg' => '两次密码不一致')));
                } else {
                    $row =  Db::table('admin')->where('admin_id', $admin_id)->save(array('password' => $enNewPwd));
                    if ($row) {
                        exit(json_encode(array('status' => 1, 'msg' => '修改成功')));
                    } else {
                        exit(json_encode(array('status' => -1, 'msg' => '修改失败')));
                    }
                }
            }
        }
        return $this->fetch();
    }

    public function admin_info()
    {
        $admin_id = $this->request->get('admin_id');
        if ($admin_id) {
            $info =  Db::table('admin')->where("admin_id", $admin_id)->find();
            $info['password'] = "";
            $this->assign('info', $info);
        }
        $act = empty($admin_id) ? 'add' : 'edit';
        $this->assign('act', $act);
        $role =  Db::table('admin_role')->select();
        $this->assign('role', $role);
        return $this->fetch();
    }

    public function adminHandle()
    {
        $data = $this->request->post();
        if (empty($data['password'])) {
            unset($data['password']);
        } else {
            $data['password'] = encrypt($data['password']);
        }
        if ($data['act'] == 'add') {
            unset($data['admin_id']);
            $data['add_time'] = time();
            if ( Db::table('admin')->where("user_name", $data['user_name'])->count()) {
                $this->error("此用户名已被注册，请更换", Url('Admin/Systems.Admin/admin_info'));
            } else {
                $r =  Db::table('admin')->add($data);
            }
        }

        if ($data['act'] == 'edit') {
            $r =  Db::table('admin')->where('admin_id', $data['admin_id'])->save($data);
        }

        if ($data['act'] == 'del' && $data['admin_id'] > 1) {
            $r =  Db::table('admin')->where('admin_id', $data['admin_id'])->delete();
            exit(json_encode(1));
        }

        if ($r) {
            $this->success("操作成功", Url('Admin/Systems.Admin/index'));
        } else {
            $this->error("操作失败", Url('Admin/Systems.Admin/index'));
        }
    }

    /*
     * 管理员登陆
     */
    public function login()
    {
		if (session('?admin_id') && session('admin_id') > 0) {
            $this->error("您已登录", url('Admin/Index/index'));
        }
		
        if (IS_POST) {
            if (tpCache('basic.verify_switch')){ // 查询验证码开关
                $verify = new Verify();
                if (!$verify->check($this->request()->post('vertify'), "admin_login")) {
                    exit(json_encode(array('status' => 0, 'msg' => '验证码错误')));
                }
            }
            $condition['user_name'] = trim($this->request()->post('username'));
            $condition['password'] = trim($this->request()->post('password'));
            if (!empty($condition['user_name']) && !empty($condition['password'])) {
                $condition['password'] = encrypt($condition['password']);
                $admin_info = Db::table('admin')->join(PREFIX . 'admin_role', PREFIX . 'admin.role_id=' . PREFIX . 'admin_role.role_id', 'INNER')->where($condition)->find();
                if (is_array($admin_info)) {
                    session('admin_id', $admin_info['admin_id']);
                    session('act_list', $admin_info['act_list']);
                    Db::table('admin')->where("admin_id = " . $admin_info['admin_id'])->save(array('last_login' => time(), 'last_ip' => $this->request()->ip(0,true)));
                    session('last_login_time', $admin_info['last_login']);
                    session('last_login_ip', $admin_info['last_ip']);
                    adminLog('后台登录');
                    $url = session('from_url') ? session('from_url') : url('Admin/Index/index');
					return json(array('status' => 1, 'url' => $url));
                } else {
					return json(array('status' => 0, 'msg' => '账号密码不正确'));
                }
            } else {
				return json(array('status' => 0, 'msg' => '请填写账号密码'));
            }
        }
		
        $this->assign('verify_switch', tpCache('basic.verify_switch'));
        return $this->fetch();
    }
	
    /**
     * 退出登陆
     */
    public function logout()
    {
        $url = session('?suppliers_id') ? url('Admin/Systems.Admin/suppliers_login') : url
		('Admin/Systems.Admin/login');
        session_unset();
        session_destroy();
        session::clear();
        $this->success("退出成功", $url);
    }

    /**
     * 验证码获取
     */
    public function vertify()
    {
        $config = array(
            'fontSize' => 30,
            'length' => 4,
            'useCurve' => true,
            'useNoise' => false,
            'reset' => false
        );
        $Verify = new Verify($config);
        $Verify->entry("admin_login");
        exit();
    }


}