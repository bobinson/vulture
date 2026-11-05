// Feature 0101, CWE-778 Concept B in Scala. Invented identifiers.
object Admin {
  def show(uid: Option[String]) = uid match {
    case Some(u) if admins(u) => Ok(view(u))
    case _ => Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
  }
  def edit(isAdmin: Boolean) =
    if (isAdmin) Ok(form)
    else
      Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
}
