package shop.dao;

import javax.persistence.EntityManager;

public class GenericDao<T> {
    private EntityManager em;
    private Class<T> entityClass;

    public Object all() {
        return em.createQuery("from " + entityClass.getSimpleName() + " where id = :id");
    }
}
