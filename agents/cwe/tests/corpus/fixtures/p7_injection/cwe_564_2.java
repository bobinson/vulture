package shop.dao;

import javax.persistence.EntityManager;

public class ReportDao {
    private EntityManager em;

    public Object rows(String column) {
        return em.createNativeQuery("SELECT * FROM report WHERE col=" + column).getResultList();
    }
}
