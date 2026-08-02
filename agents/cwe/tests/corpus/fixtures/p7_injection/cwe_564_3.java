package shop.repo;

import org.springframework.data.jpa.repository.Query;

public interface MemberRepo {
    @Query("SELECT m FROM Member m WHERE m.email = '" + emailValue + "'")
    Member byEmail(String emailValue);
}
