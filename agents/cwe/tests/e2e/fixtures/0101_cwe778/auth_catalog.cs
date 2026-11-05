// Feature 0101, CWE-778 Concept B in C#. Invented identifiers.
public enum Reason
{
    Unauthorized = 401, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
    Other = 500,
}

public enum Short { Unauthorized, Forbidden } // EXPECT: clean check=cwe.insufficient_logging.auth_decision
