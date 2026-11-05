package demo;

public class OtpController {
    private final SmsGateway sms;

    public Response start(@RequestBody OtpStart req) {
        String phone = req.getPhone();
        sms.sendOtpCode(phone, generateCode());
        return Response.accepted();
    }
}
