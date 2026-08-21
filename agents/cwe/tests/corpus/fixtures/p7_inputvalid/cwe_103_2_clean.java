public class SearchForm extends ValidatorActionForm {
    private String term;

    public ActionErrors validate(final ActionMapping mapping, HttpServletRequest req) {
        return super.validate(mapping, req);
    }
}
