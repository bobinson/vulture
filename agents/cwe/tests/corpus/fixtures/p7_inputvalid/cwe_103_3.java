public class CheckoutForm extends ValidatorForm {
    private String card;

    public ActionErrors validate(ActionMapping mapping, HttpServletRequest request) {
        ActionErrors errors = new ActionErrors();
        errors.add("card", new ActionMessage("errors.card"));
        return errors;
    }
}
