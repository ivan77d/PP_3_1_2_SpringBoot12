package com.example.pp_3_1_2_springboot.service;

import com.example.pp_3_1_2_springboot.model.User;

import java.util.List;

public interface UserService {

    List<User> allUsers();

    User userById(int id);

    void save(User user);

    void update(User user);

    void delete(int id);

    User getUserByLogin(String username);
}