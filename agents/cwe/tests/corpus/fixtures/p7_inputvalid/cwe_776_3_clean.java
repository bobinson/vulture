public final class ReportTransformer {
    public Transformer build() throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return tf.newTransformer();
    }
}
