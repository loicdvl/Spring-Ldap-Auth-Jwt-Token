package com.loicdev.springdemo.controller;

import javax.validation.Valid;
import javax.validation.constraints.Min;

import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.loicdev.springdemo.api.model.CategoryDTO;
import com.loicdev.springdemo.api.model.CategoryListDTO;
import com.loicdev.springdemo.service.CategoryService;

@Validated
@RestController
@RequestMapping(CategoryController.BASE_URL)
public class CategoryController {

	public static final String BASE_URL = "/api/v1/categories";

    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public CategoryListDTO getallCatetories(){
        return new CategoryListDTO(categoryService.getAllCategories());
    }

    @GetMapping("{name}")
    @ResponseStatus(HttpStatus.OK)
    public CategoryDTO getCategoryByName(@PathVariable String name){
        return categoryService.getCategoryByName(name);
    }
    
    @PostMapping
    //@PreAuthorize("hasRole('ROLE_DEVELOPERS')")
    @ResponseStatus(HttpStatus.CREATED)
    public CategoryDTO createCategory(@Valid @RequestBody CategoryDTO categoryDTO) {
    	return categoryService.create(categoryDTO);
    }
    
    @PutMapping("{id}")
    @ResponseStatus(HttpStatus.OK)
    public CategoryDTO updateCategory(@PathVariable @Min(1) Long id, @Valid @RequestBody CategoryDTO categoryDTO) {
    	return categoryService.update(id, categoryDTO);
    }
    
    @DeleteMapping("{id}")
    @ResponseStatus(HttpStatus.OK)
    public CategoryDTO deleteCategory(@PathVariable @Min(1) Long id) {
    	CategoryDTO categoryDTO = categoryService.findById(id);
    	
    	categoryService.deleteById(id);
    	
    	return categoryDTO;
    }
}
