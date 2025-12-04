package com.example.demo.controller;

import com.example.demo.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class StudentController {

    private List<Student> students = new ArrayList<>(List.of(
            new Student(1,"vivin",23),
            new Student (2,"inna",43)
    ));

    @GetMapping("/")
    public List<Student> listStudent() {
        return students;
    }
}
