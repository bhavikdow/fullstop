<?php
defined('BASEPATH') or exit('No direct script access allowed');
class Api_model extends CI_Model{

    public function __construct(){
        parent::__construct();
        $this->load->model(['Api_model']);
    }

    public function checkEmail($email){
        $this->db->select('*');
        $this->db->from('users');
        $this->db->where(['email'=>$email,'status !='=>'Deleted']);
        return $this->db->get()->row_array();
    }

    public function updateOtp($otp,$user_id){
        $this->db->where('user_id',$user_id);
        $this->db->update('users',['otp'=> $otp]);
        return true;
    }

    public function doSignup($otp){
        try{
            $data=array(
                'name'=>$this->input->post('name'),
                'email'=>$this->input->post('email'),
                'password'=>hash('sha256',$this->input->post('password')),
                'otp'=>$otp,
                'is_verify'=>'no',
                'status'=>'Active'
            );
            $this->db->insert('users', $data);
            $id = $this->db->insert_id();
            $result = $this->db->get_where('users', ['user_id' => $id]);
            return $result->row_array();
        }catch(\Exception $e){
            echo $e->getMessage();
            return false;
        }
    }

    // insert token
    public function insertToken($user_id, $token,$device_type){
        try{
            $this->db->insert('users_authentication', array('user_id' => $user_id, 'user_token' => $token,'device_type'=>$device_type));
            $this->db->insert_id();
        }catch(\Exception $e){
            return false;
        }
       
    }

    public function updateToken($user_id, $token){
        try{
            $this->db->update('users_authentication', ['user_token' => $token], ['user_id' => $user_id]);
            return $this->db->affected_rows();
        }catch(\Exception $e){
            return false;
        }
       

    }

    public function getToken($pid){
        try{
            $this->db->select('*');
            $this->db->from('users_authentication');
            $this->db->where('user_id', $pid);
            return $this->db->get()->row_array();
        }catch(\Exception $e){
            return false;
        }
        
    }
    
    // firbase token
    public function checkTokenid($token_id, $user_id){
        try{
            $query = $this->db->get_where('users_authentication', ['user_id' => $user_id, 'firebase_token' => $token_id]);
            return $query->row_array();
        }catch(Exception $e){
            return false;
        }
       
    }

    public function deleteToken($user_id){
        try{
            $this->db->where('user_id',$user_id);
            $query = $this->db->update('users_authentication', ['firebase_token' =>NULL]);
            return $this->db->affected_rows();
        }catch(Exception $e){
            return false;
        }
    }

    public function updatefToken($user_id, $token_id,$device_type){
        try{
            $this->db->where('user_id',$user_id);
            $query = $this->db->update('users_authentication', ['firebase_token' =>$token_id,'device_type'=>$device_type]);
            return $this->db->affected_rows();
        }catch(Exception $e){
            return false;
        }
       
    }

    public function updateVerifyStatus($user_id){
        try{
            $this->db->where('user_id',$user_id);
            $this->db->update('users',['is_verify'=>'yes']);
            return true;
        }catch(Exception $e){
            return false;
        }
        
    }
    
    public function updateProfile($user_id){
        try{
            $data = array(
                'name' => $this->input->post('name'),
            );
            $this->db->where('user_id',$user_id);
            $this->db->update('users',$data);
            return true;
        }catch(Exception $e){
            return false;
        }
        
    }

    public function sendOtp($otp, $user_id){
        try{
            $otpexpire = date('Y-m-d h:i:s', strtotime('+5 minutes', strtotime(date('Y-m-d h:i:s'))));
            $data = array(
                'otp' => $otp,
                // 'otp_expiry' => $otpexpire,
            );
            $this->db->where('user_id', $user_id);
            $this->db->update('users', $data);
            return $this->db->affected_rows();
        }catch(Exception $e){
            return false;
        } 
    }

    public function getUserByEmail($email){
        try{
            $this->db->where('u.email', $email);
            $this->db->select('u.user_id,u.name,u.email,ua.user_token,ua.firebase_token');
            $this->db->from('users u');
            $this->db->join('users_authentication ua', 'u.user_id=ua.user_id');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
    }

    public function getUserByUserId($user_id){
        try{
            $this->db->where('u.user_id', $user_id);
            $this->db->select('u.user_id,u.name,u.email,ua.user_token,ua.firebase_token,u.otp');
            $this->db->from('users u');
            $this->db->join('users_authentication ua', 'u.user_id=ua.user_id');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
       
    }
   
    public function verifyOtp($otp, $user_id){
        try{
            $this->db->select('user_id, otp, otp_expiry');
            $this->db->from('users');
            $this->db->where('otp', $otp);
            $this->db->where('user_id', $user_id);
            $this->db->where('status', 'Active');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
        
    }

    public function emailVerify($email){
        try{
            $this->db->where('email', $email);
            $this->db->select('email,user_id,name,status,is_verify,is_blocked');
            $this->db->from('users');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
       
    }

    public function doLogin(){
        try{
            $data = array(
                'email' => $this->security->xss_clean($this->input->post('email')),
                'password' => $this->security->xss_clean(hash('sha256', $this->input->post('password'))),
            );
            $this->db->where($data);
            $this->db->select('user_id,status,is_verify');
            $this->db->from('users');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
       
    }
    
    public function checkSocialUserData($email){
        try{
            $result = $this->db->get_where('users', ['email' => $email, 'status !=' => 'Deleted']);
            return $result->row_array();
        }catch(Exception $e){
            return false;
        }
     
    }

    public function insertSocialUserData($social_type, $email, $social_id,$name){
        try{
            $data = array(
                'email' => $email,
                'name'  =>$name,
                'source' => $social_type,
                'social_id' => $social_id,
                'is_verify' => 'yes',
            );
            $this->db->insert('users', $data);
            return $this->db->insert_id();
        }catch(Exception $e){
            return false;
        }
        
    }

    public function updateSocialUserData($social_type, $email, $social_id,$name){
        try{
            $data = array(
                'email' => $email,
                'source' => $social_type,
                'name'  =>$name,
                'social_id' => $social_id,
                'status' => 'Active',
                'is_verify' => 'yes'
            );
            $this->db->update('users', $data, ['email' => $email]);
            return $this->db->affected_rows();
        }catch(Exception $e){
            return false;
        }
        
    }

    public function getPages($page){
        try{
            $this->db->select('description, type as page_name');
            $this->db->from('setting');
            $this->db->where(['type' => $page]);
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
       
    }

    public function checkoldpassword($old_pass, $user_id){
        try{
            $this->db->select('*');
            $this->db->from('users');
            $this->db->where('password', hash('sha256', $old_pass));
            $this->db->where('user_id', $user_id);
            $sel = $this->db->get();
            return $sel->row_array();
        }catch(Exception $e){
            return false;
        }
     
    }

    // change password
    public function changePassword($user_id, $old_pass, $new_pass){
        try{
            $old_p = hash('sha256', $old_pass);
            $this->db->select('*');
            $this->db->from('users');
            $where = "user_id = '$user_id' AND password = '$old_p'";
            $this->db->where($where);
            $query = $this->db->get();
            if ($query->num_rows() > 0) {
                $this->db->where('user_id', $user_id);
                $q = $this->db->update('users', ['password' => hash('sha256', $new_pass)]);
                return true;
            } else {
                return false;
            }
        }catch(Exception $e){
            return false;
        }
       
    }
    public function resetPassword($user_id, $new_pass){
        try{
            $this->db->select('*');
            $this->db->from('users');
            $this->db->where(['user_id' => $user_id]);
            $query = $this->db->get();
            if ($query->num_rows() > 0) {
                $this->db->where('user_id', $user_id);
                $this->db->update('users', ['password' => hash('sha256', $new_pass)]);
                return true;
            } else {
                return false;
            }
        }catch(Exception $e){
            return false;
        }
        
    }
    public function getUserByToken($token){
        try{
            $this->db->select('u.user_id,u.name,u.email,u.is_verify,u.status,ua.user_token,ua.firebase_token');
            $this->db->from('users u');
            $this->db->where('ua.user_token', $token);
            $this->db->join('users_authentication ua', 'u.user_id=ua.user_id');
            $this->db->where('u.status','Active');
            $this->db->order_By('user_id', 'desc');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
    }
    public function viewProfile($user_id){
        try{
            $this->db->select('*');
            $this->db->from('users');
            $this->db->where('user_id',$user_id);
            $qry=$this->db->get();
            return $qry->row_array();
        }catch(Exception $e){
            return false;
        }
        
    }
    public function sendEmailOtp($otp, $user_id){
        try{
            $otpexpire = date('Y-m-d h:i:s', strtotime('+5 minutes', strtotime(date('Y-m-d h:i:s'))));
            $data = array(
                'user_id'=>$user_id,
                'otp' => $otp,
                'otp_expiry' => $otpexpire,
                'status'    =>'0'
            );
            $this->db->insert('email_verify', $data);
            $id= $this->db->insert_id();
            $this->db->where('verify_email_id',$id);
            $this->db->from('email_verify');
            $this->db->order_by('verify_email_id','desc');
            return $this->db->get()->row_array();
        }catch(Exception $e){
            return false;
        }
        
    }
    public function deleteAccount($user_id){
        try{
            $this->db->where('user_id', $user_id);
            // $this->db->where('status', 'Active');
            $this->db->update('users', ['status' => 'Deleted']);
            return $this->db->affected_rows();
        }catch(Exception $e){
            return false;
        }  
    }

    public function getBrands(){
        $this->db->select('*');
        $this->db->from('brand');
        return $this->db->get()->result_array();
    }
    public function getModelByModelid($id){
        $this->db->select('*');
        $this->db->from('model');
        $this->db->where('brand_id',$id);
        return $this->db->get()->result_array();
    }
    public function insert($data){
        $this->db->insert('brand',$data);
    }
}