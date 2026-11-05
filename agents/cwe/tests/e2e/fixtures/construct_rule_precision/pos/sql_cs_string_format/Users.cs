public class Users {
    public object Find(SqlConnection db, string id) {
        var cmd = new SqlCommand(string.Format("SELECT * FROM users WHERE id = '{0}'", id), db); // EXPECT: finding
        return cmd.ExecuteReader();
    }
}
