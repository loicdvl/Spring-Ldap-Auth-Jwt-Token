package com.loicdev.springdemo.api.model;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CategoryListDTO {

	List<CategoryDTO> categories;
}
