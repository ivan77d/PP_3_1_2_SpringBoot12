package com.example.pp_3_1_2_springboot.dao;


import com.example.pp_3_1_2_springboot.model.User;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import java.util.List;

@Repository
public class UserDaoImpl implements UserDao {
    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<User> userList() {
        return entityManager.createQuery("select user from User user", User.class).getResultList();
    }

    @Override
    public User userById(int id) {
        return entityManager.find(User.class, id);
    }

    @Override
    public void save(User user) {
        entityManager.persist(user);
    }

    @Override
    public void update(User user) {
        entityManager.merge(user);
    }

    @Override
    public void delete(int id) {
        User user = entityManager.find(User.class, id);
        entityManager.remove(user);
    }

    @Override
    public User getUserByLogin(String username) {
        return entityManager
                .createQuery("select user from User user where user.username = :username", User.class)
                .setParameter("username", username).getSingleResult();
    }
}
