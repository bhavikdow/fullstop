<?php

defined('BASEPATH') or exit('No direct script access allowed');
class Api extends CI_Controller
{

    public function __construct()
    {
        parent::__construct();
        $this->load->model(['Api_model']);
    }

    public function uniqueId()
    {
        $str = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNIPQRSTUVWXYZ';
        $nstr = str_shuffle($str);
        $unique_id = substr($nstr, 0, 10);
        return $unique_id;
    }

    //----------------------------- Upload single file-----------------------------
    public function doUploadImage($path, $file_name)
    {
        $config = array(
            'upload_path' => $path,
            'allowed_types' => "jpeg|jpg|png|pdf",
            'file_name' => rand(11111, 99999),
            'max_size' => "5120",
        );
        $this->load->library('upload', $config);
        $this->upload->initialize($config);
        if ($this->upload->do_upload($file_name)) {
            $data = $this->upload->data();
            return $data['file_name'];
        } else {
            return $this->upload->display_errors();
        }
    }

    //----------------------------- Upload multiple files-------------------------------------------
    public function upload_files($path, $file_name)
    {
        $this->output->set_content_type('application/json');
        $files = $_FILES[$file_name];
        $config = array(
            'upload_path' => $path,
            'allowed_types' => 'jpeg|jpg|gif|png|pdf',
            'overwrite' => 1,
        );
        $this->load->library('upload', $config);
        $images = array();
        $i = 0;
        foreach ($files['name'] as $key => $image) {
            $_FILES['images[]']['name'] = $files['name'][$key];
            $_FILES['images[]']['type'] = $files['type'][$key];
            $_FILES['images[]']['tmp_name'] = $files['tmp_name'][$key];
            $_FILES['images[]']['error'] = $files['error'][$key];
            $_FILES['images[]']['size'] = $files['size'][$key];

            $title = rand('1111', '9999');
            $image = explode('.', $image);
            $count = count($image);
            $extension = $image[$count - 1];
            $fileName = $title . '.' . $extension;
            $images[$i] = $fileName;
            $config['file_name'] = $fileName;
            $this->upload->initialize($config);

            if ($this->upload->do_upload('images[]')) {
                $this->upload->data();
            } else {
                return $this->upload->display_errors();
            }
            $i++;
        }
        return $images;
    }

    public function genrateToken()
    {
        $token = openssl_random_pseudo_bytes(16);
        $token = bin2hex($token);
        return $token;
    }

    public function sendMail($data)
    {
        $this->load->library('email');
        $to = $data['email'];
        $subject = $data['subject'];
        $message = $data['message'];
        $header = "from:admin@fullstop.com \r\n";
        $header .= "MIME-Version: 1.0\r\n";
        $header .= "Content-type: text/html\r\n";
        $retval = mail($to, $subject, $message, $header);
        return true;
    }

    public function AuthorizationToken(){
        $user_token = $this->input->get_request_header('token');
        $user_data = $this->Api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User already logged in on a different device']));
            return false;
        }
        if($user_data['status'] == 'Inactive'){
            header('HTTP/1.1 402 User is Inactive', true, 402);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User Is Inactive By Admin','data' => $user_data]));
            return false;
        }
        if($user_data['is_verify'] == 'no'){
            header('HTTP/1.1 200 User is Reviww', true, 200);
            $this->output->set_output(json_encode(['result' => -2, 'msg' => 'User Is Review By Admin and verify very soon','data' => $user_data]));
            return false;
        }
        return $user_data['user_id'];
    }

    public function doSignup()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('email', 'Email ID ', 'required|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'required');
        $this->form_validation->set_rules('confirm_password', 'Confirm Password', 'required|matches[password]');
        if ($this->form_validation->run() === false) {
            $validation = $this->form_validation->error_array();
            foreach ($validation as $key => $value) {
                $this->output->set_output(json_encode(['result' => 0, 'errors' => $value]));
                return false;
            }
        }
        $checkMail = $this->Api_model->checkEmail($this->input->post('email'));
        // genrate otp
        // $otp = rand(11111, 99999);
         $otp = 1234;
        if (!empty($checkMail)) {
            if ($checkMail['is_verify'] == 'no') {
                $this->Api_model->updateOtp($otp, $checkMail['user_id']);
                $this->sendVerificationMail($checkMail['user_id']);
                $this->output->set_output(json_encode(['result' => 4, 'msg' => 'Otp Screen Again.', 'data' => $checkMail]));
                return false;
            }
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'E-Mail-ID Already Exists.']));
            return false;
        }

        $result = $this->Api_model->doSignup($otp);
        if ($result) {
            // Token insert
            $device_type = $this->input->post('device_type');
            $this->Api_model->insertToken($result['user_id'], $this->genrateToken(), $device_type);
            $response = $this->Api_model->getUserByUserId($result['user_id']);

            //$this->sendVerificationMail($result['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Please Enter an OTP.', 'data' => $response]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'opps Some thing went wrong !!!']));
            return false;
        }
    }

    public function sendVerificationMail($user_id)
    {
        $user = $this->Api_model->getUserByUserId($user_id);
        $userEmail = $user['email'];
        $fromEmail = 'support@fullstop.com';
        $subject = 'Email Verification | Helath';
        $htmlContent = "<h3>Hi,</h3>";
        $htmlContent .= "Welcome To FullStop!!<br />";
        $htmlContent .= "Your Otp Is.<br />";
        $htmlContent .= $user['otp'];
        $user_id = $user['user_id'];
        $htmlContent .= "";
        $mail_data['subject'] = $subject;
        $mail_data['message'] = $htmlContent;
        $mail_data['email'] = $userEmail;
        $result = $this->sendMail($mail_data);
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Email Sent to your Registered Email Id']));
            return true;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something Went Wrong.']));
            return false;
        }
    }

    public function sendOtp()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('email', 'Email ', 'required|valid_email');
        if ($this->form_validation->run() === false) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => $this->form_validation->error_array()]));
            return false;
        }
        $email = $this->input->post('email');
        $is_email = $this->Api_model->getUserByEmail($email);
        if (empty($is_email)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email is not present in our database.']));
            return false;
        }
        // $otp = mt_rand(11111, 99999);
        $otp = 12345;
        $result = $this->Api_model->sendOtp($otp, $is_email['user_id']);
        if ($result) {
            // for mail
            $mail['subject'] = 'Otp For Login!';
            $mail['message'] = 'Your Otp Is' . $otp;
            $mail['email'] = $is_email['email'];
            $this->sendMail($mail);
            $result = $this->Api_model->getUserByUserId($is_email['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Send Successfully', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Failed to send otp.']));
        }
    }

    public function otpVerification()
    {
        $this->output->set_content_type('application/json');
        $user_id = $this->input->post('user_id');
        $otp = $this->input->post('otp');
        if (empty($user_id)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'User ID is Required!!.']));
            return false;
        }
        if (empty($otp)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Otp Required.']));
            return false;
        }
        $current_time = date('Y-m-d h:i');
        $result = $this->Api_model->verifyOtp($otp, $user_id);
        if ($result) {
            /*if (strtotime($result['otp_expiry']) < strtotime($current_time)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Otp Expired. Please Request New Otp']));
            return false;
            }*/
            $this->Api_model->updateVerifyStatus($user_id);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Verified Successfully.', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Invaid Otp.']));
        }
    }

    public function updateProfile()
    {
        $this->output->set_content_type('application/json');
        $user_id =$this->AuthorizationToken();
        if($user_id== false){
            return false;
        }
        
        $result = $this->Api_model->updateProfile($user_id);
        if ($result) {
            $result = $this->Api_model->getUserByUserId($user_id);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Profile updated successfully', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Update failed', 'data' => null]));
            return false;
        }
    }

    public function doLogin()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('email', 'Email ID ', 'required|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'required');
        if ($this->form_validation->run() === false) {
            $validation = $this->form_validation->error_array();
            foreach ($validation as $key => $value) {
                $this->output->set_output(json_encode(['result' => 0, 'errors' => $value]));
                return false;
            }
        }
        $email = $this->input->post('email');

        $checkemail = $this->Api_model->emailVerify($email);
       
        if (!empty($checkemail)) {
            if ($checkemail['is_blocked'] == 'yes') {
                $userdata1=$this->Api_model->getUserByUserId($checkemail['user_id']);
                //$this->sendVerificationMail($checkemail['user_id']);
                header('HTTP/1.1 200 Otp verify.', true,200);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your account has been blocked by admin.','data' =>$userdata1 ]));
                return false;
            }
            if ($checkemail['is_verify'] == 'no') {
                $userdata1=$this->Api_model->getUserByUserId($checkemail['user_id']);
                //$this->sendVerificationMail($checkemail['user_id']);
                header('HTTP/1.1 200 Otp verify.', true,200);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'verify otp.','data' =>$userdata1 ]));
                return false;
            }
            if ($checkemail['status'] == 'Deleted') {
                header('HTTP/1.1 200 User Account has been deleted.', true, 200);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your Account has been deleted.']));
                return false;
            }
            if ($checkemail['status'] == 'Blocked') {
                header('HTTP/1.1 200 User Account Is Blocked.', true, 200);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your Account has been blocked!!']));
                return false;
            }
            if ($checkemail['status'] == 'Inactive') {
                header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
                $this->output->set_output(json_encode(['result' => -2, 'msg' => 'Your Account has been Inactive!!']));
                return false;
            }
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email Does not exist']));
            return false;
        }
        $results = $this->Api_model->doLogin();
        if ($results) { 
            if ($results['is_verify'] == 'no') {
                $userdata=$this->Api_model->getUserByUserId($results['user_id']);
                $this->output->set_output(json_encode(['result' => 3, 'msg' => 'Your Account is not verified !!', 'data' => $userdata]));
                return false;
            }
            $this->Api_model->updateToken($results['user_id'], $this->genrateToken());
            $result = $this->Api_model->getUserByUserId($results['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Login Successfully !!', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email or Password is Incorrect !! ', 'data' => null]));
            return false;
        }
    }

    public function getPages()
    {
        $this->output->set_content_type('application/json');
        $page = $this->input->post('page');
        if (empty($page)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Page Name Required!!.']));
            return false;
        }
        $result = $this->Api_model->getPages($page);
        if (!empty($result)) {
            if ($result['page_name'] == 'helpsupport') {
                $result['page_name'] = "helpsupport";
            }
            if ($result['page_name'] == 'termsconditions') {
                $result['page_name'] = "termsconditions";
            }
            if ($result['page_name'] == 'privacypolicy') {
                $result['page_name'] = "privacypolicy";
            }
            $str = ["&nbsp;", "&#39;"];
            $rplc = [" ", "'"];
            $description = str_replace($str, $rplc, ($result['description']));
            $result['description'] = $description;
        }
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Pages Data', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Record Found!!']));
        }
    }

    // for forgot password
    public function forgotPassword()
    {
        $this->output->set_content_type('application/json');
        $email = $this->input->post('email');
        if (empty($email)) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => 'Email Address Is Required !!!.', 'data' => null]));
            return false;
        }
        $mail_exist = $this->Api_model->emailVerify($email);
        if ($mail_exist) {
            // $otp = mt_rand(1111, 9999);
            $otp = 1234;
            // for mail
            $mail['subject'] = 'Otp For Forgot Password!';
            $mail['message'] = 'Otp Is' . $otp;
            $mail['email'] = $mail_exist['email'];
             $this->sendMail($mail);
            $result = $this->Api_model->sendOtp($otp, $mail_exist['user_id']);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Sent Your Email.', 'data' => ['user_id' => $mail_exist['user_id'], 'email' => $mail_exist['email'], 'otp' => $otp]]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email Is Not Present In Our Database.', 'data' => null]));
            return false;
        }
    }

    public function changePassword()
    {
        $this->output->set_content_type('application/json');
        $user_id =$this->AuthorizationToken();
        if($user_id== false){
            return false;
        }
        $old_pass = $this->input->post('old_password');
        $new_pass = $this->input->post('new_password');
        $c_pass = $this->input->post('confirm_password');
        $checkold = $this->Api_model->checkoldpassword($old_pass, $user_id);
        if ($checkold) {
            if ($old_pass == $new_pass) {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and old password should not be the same.']));
            } else {
                if ($new_pass == $c_pass) {
                    $result = $this->Api_model->changePassword($user_id, $old_pass, $new_pass);
                    if ($result) {
                        $this->output->set_output(json_encode(['result' => 1, 'msg' => 'The password was changed successfully']));
                    } else {
                        $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password update failed']));
                    }
                } else {
                    $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and confirmation password do not match.']));
                }
            }
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'The old password is incorrect.']));
        }
    }

    public function resetPassword()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('new_password', 'New Password ', 'required');
        $this->form_validation->set_rules('confirm_password', 'Confirm Password', 'required|matches[new_password]');
       // $this->form_validation->set_rules('user_id', 'User ID', 'required');
        if ($this->form_validation->run() === false) {
            $validation = $this->form_validation->error_array();
            foreach ($validation as $key => $value) {
                $this->output->set_output(json_encode(['result' => 0, 'errors' => $value]));
                return false;
            }
        }
        $user_id = $this->input->post('user_id');
        $new_pass = $this->input->post('new_password');
        $c_pass = $this->input->post('confirm_password');
        if ($new_pass != $c_pass) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New Password and Confirm password should be the same.']));
        } else {
            if ($new_pass == $c_pass) {
                $result = $this->Api_model->resetPassword($user_id, $new_pass);
                if ($result) {
                    $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Password reset successfully']));
                } else {
                    $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password update failed']));
                }
            } else {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and confirmation password do not match.']));
            }
        }
    }

    public function viewProfile()
    {
        $this->output->set_content_type('application/json');
        $user_id =$this->AuthorizationToken();
        if($user_id== false){
            return false;
        }
        $result = $this->Api_model->viewProfile($user_id);
        if ($result) {
            $response = $this->Api_model->getUserByUserId($user_id);
            
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Profile fetched Successfully !!', 'data' => $response]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Falied to view', 'data' => null]));
            return false;
        }
    }

    public function getNotification()
    {
        $this->output->set_content_type('application/json');
        $user_id =$this->AuthorizationToken();
        if($user_id== false){
            return false;
        }
        $result = $this->Api_model->getNotification($user_id);
        $i = 0;
        foreach ($result as $row) {
            $result[$i]['notification_date_time'] = changeDateFormat($row['created_at']);
            $i++;
        }

        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Patient History', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No record Found !!.']));
        }
    }

    public function emailChange()
    {
        $this->output->set_content_type('application/json');
        $user_id =$this->AuthorizationToken();
        if($user_id== false){
            return false;
        }
        $email = $this->input->post('email');
        if (empty($email)) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => 'Email is Required!!!.', 'data' => null]));
            return false;
        }
        $mail_exist = $this->Api_model->emailVerify($email);
        if (!$mail_exist) {
            //$otp = mt_rand(11111, 99999);
            $otp = 12345;
            // for mail
            $mail['subject'] = 'Otp For Email Change!';
            $mail['message'] = 'Your Otp Is ' . $otp;
            $mail['email'] = $email;
            $this->sendMail($mail);
            $result = $this->Api_model->sendEmailOtp($otp, $email);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Sent on your mail.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'User Already exist.', 'data' => null]));
            return false;
        }
    }

    public function sendEmailOtp()
    {
        $this->output->set_content_type('application/json');
        $this->form_validation->set_rules('email', 'Email ', 'required|valid_email');
        if ($this->form_validation->run() === false) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => $this->form_validation->error_array()]));
            return false;
        }
        $email = $this->input->post('email');
        $user_id = $this->input->post('user_id');
        if (empty($email)) {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Email is required.']));
            return false;
        }
        $otp = mt_rand(11111, 99999);
        $otp = 12345;
        $result = $this->Api_model->sendEmailOtp($otp, $user_id);
        if ($result) {
            // for mail
            $mail['subject'] = 'Otp For Email!';
            $mail['message'] = 'Your Otp Is' . $otp;
            $mail['email'] = $email;
            $this->sendMail($mail);
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Otp Send Successfully', 'data' => $result]));
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Failed to send otp.']));
        }
    }

    public function updatePassword()
    {
        $this->output->set_content_type('application/json');
        $user_id = $this->input->post('user_id');
        $new_pass = $this->input->post('new_password');
        $c_pass = $this->input->post('confirm_password');
        if ($new_pass == $c_pass) {
            $result = $this->Api_model->updatePassword($user_id, $new_pass);
            if ($result) {
                $this->output->set_output(json_encode(['result' => 1, 'msg' => 'password update']));
            } else {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Password update failed']));
            }
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'New and confirmation password do not match.']));
        }
    }

    public function setToken()
    {
        $this->output->set_content_type('application/json');
        $user_id = $this->input->post('user_id');
        $token_id = $this->input->post('firebase_token');
        $device_type = $this->input->post('device_type');
        $check = $this->Api_model->checkTokenid($token_id, $user_id);
        if ($check) {
            $this->output->set_output(json_encode(['result' => 0, 'msg' => 'Token Already Exists', 'data' => null]));
            return false;
        } else {
            $this->Api_model->deleteToken($user_id);
            $result = $this->Api_model->updatefToken($user_id, $token_id, $device_type);
            if ($result) {
                $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Token Id Updated']));
                return false;
            } else {
                $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Fail To Update Token Id', 'data' => null]));
                return false;
            }
        }
    }

    public function verifyemail($user_id)
    {
        $user_id = decryptId($user_id);
        $data['result'] = $this->Api_model->verifyemail($user_id);
        $data['title'] = 'Verify Email';
        $this->load->view('admin/verifyemail', $data);
    }

    public function socialLogin()
    {
        $this->output->set_content_type('application/json');
        $social_type = $this->input->post('source');
        $name = $this->input->post('name');
        $email = $this->input->post('email');
        $social_id = $this->input->post('social_id');
        $device_type = $this->input->post('device_type');
        $token = $this->genrateToken();
        $checkmail = $this->Api_model->checkSocialUserData($email);
        $userdata = $this->Api_model->checkSocialUserData($email);
        if (empty($checkmail)) {
            $insert_social_data = $this->Api_model->insertSocialUserData($social_type, $email, $social_id, $name);
            $this->Api_model->insertToken($insert_social_data, $this->genrateToken(), $device_type);
        } else {
            if ($checkmail['status'] == 'Blocked') {
                $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Your account has been blocked.', 'data' => null]));
                return false;
            } else {
                $update_social_data = $this->Api_model->updateSocialUserData($social_type, $email, $social_id, $name);
                $this->Api_model->updateToken($userdata['user_id'], $this->genrateToken(), $device_type);
            }
        }
        $userdata = $this->Api_model->checkSocialUserData($email);
        $result = $this->Api_model->getUserByUserId($userdata['user_id']);
        if (!empty($userdata['image_url'])) {
            $userdata['image_url'] = base_url('uploads/users/' . $userdata['image_url']);
        } else {
            $userdata['image_url'] = null;
        }

        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Logged In Successfully.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Not Authentication !!.', 'data' => []]));
            return false;
        }
    }

    public function deleteAccount()
    {
        $this->output->set_content_type('application/json');
        $user_id =$this->AuthorizationToken();
        if($user_id== false){
            return false;
        }
        $result = $this->Api_model->deleteAccount($user_id);
        if ($result) {
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Account deleted successfully.', 'data' => $result]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Something went wrong', 'data' => null]));
            return false;
        }
    }
    public function getBrands(){
        $this->output->set_content_type('application/json');
        $result = $this->Api_model->getBrands();
        if ($result) {
            $response = $result;
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Brands  !!', 'data' => $response]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'No Brand Found', 'data' => null]));
            return false;
        }
    }
    public function getModel(){
        $this->output->set_content_type('application/json');
        $brand_id=$this->input->post('brand_id');
        if(empty($brand_id)){
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Brand ID is Required!!']));
            return false;
        }
        $result = $this->Api_model->getModelByModelid($brand_id);
        if ($result) {
            $response = $result;
            $this->output->set_output(json_encode(['result' => 1, 'msg' => 'Modeles  !!', 'data' => $response]));
            return false;
        } else {
            $this->output->set_output(json_encode(['result' => -1, 'msg' => 'Falied to view', 'data' => null]));
            return false;
        }
    }

   

}