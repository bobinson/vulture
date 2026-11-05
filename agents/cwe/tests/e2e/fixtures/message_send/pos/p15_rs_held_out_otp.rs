use crate::sms::send_otp_sms;

pub async fn request_code(form: Form<CodeRequest>) -> StatusCode {
    let phone = form.phone.trim().to_string();
    let code = random_code();
    send_otp_sms(&phone, &code).await;
    StatusCode::ACCEPTED
}
