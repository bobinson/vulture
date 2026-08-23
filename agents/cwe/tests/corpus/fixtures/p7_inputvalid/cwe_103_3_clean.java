public abstract class BaseCheckoutForm extends ValidatorForm {
    private String card;

    public ActionErrors validate(ActionMapping mapping, HttpServletRequest request) {
        return new ActionErrors();
    }
}
