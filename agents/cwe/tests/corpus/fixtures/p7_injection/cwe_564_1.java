package shop.dao;

import javax.persistence.EntityManager;

public class AccountDao {
    private EntityManager em;

    public Object findByName(String name) {
        return em.createQuery("from Account where name='" + name + "'").getSingleResult();
    }
}
