package com.example.pp_3_1_2_springboot.controllers;



import com.example.pp_3_1_2_springboot.model.User;
import com.example.pp_3_1_2_springboot.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Controller
@RequestMapping("/user")
public class UsersControllers {

    private UserServiceImpl userService;

    @Autowired
    public UsersControllers(UserServiceImpl userService) {
        this.userService = userService;
    }

    @GetMapping
    public String getUser(Principal principal, Model model) {
        User user = userService.getUserByLogin(principal.getName());
        model.addAttribute("user", user);
        model.addAttribute("roles", user.getRoles());
        return "user";
    }
}
