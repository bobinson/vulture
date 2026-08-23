package shop.dao;

import javax.persistence.EntityManager;

public class ListingDao {
    private static final String BASE_HQL = "from Listing";
    private static final String ORDER_CLAUSE = " order by createdAt desc";
    private EntityManager em;

    public Object all() {
        return em.createQuery(BASE_HQL + ORDER_CLAUSE).getResultList();
    }
}
