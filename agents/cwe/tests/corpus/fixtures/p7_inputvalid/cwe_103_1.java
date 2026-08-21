public class ProfileForm extends ValidatorForm {
    private String email;

    public ActionErrors validate(ActionMapping mapping, HttpServletRequest request) {
        ActionErrors errors = new ActionErrors();
        if (email == null) {
            errors.add("email", new ActionMessage("errors.required"));
        }
        return errors;
    }
}
