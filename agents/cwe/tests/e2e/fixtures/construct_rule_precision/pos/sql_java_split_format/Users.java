class Users {
    ResultSet find(Statement stmt, String cols) throws Exception {
        String q = String.format("SELECT %s", cols); // EXPECT: finding
        q += " FROM accounts";
        return stmt.executeQuery(q);
    }
}
