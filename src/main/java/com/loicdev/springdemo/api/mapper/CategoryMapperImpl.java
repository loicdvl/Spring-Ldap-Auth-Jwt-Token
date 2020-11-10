package com.loicdev.springdemo.api.mapper;

import org.springframework.stereotype.Component;

import com.loicdev.springdemo.api.model.CategoryDTO;
import com.loicdev.springdemo.domain.Category;

@Component
public class CategoryMapperImpl implements CategoryMapper {

	@Override
	public CategoryDTO categoryToCategoryDTO(Category category) {
		if(category == null)
			return null;
		
		CategoryDTO categoryDTO = new CategoryDTO();
		categoryDTO.setId(category.getId());
		categoryDTO.setName(category.getName());
		
		return categoryDTO;
	}

	@Override
	public Category CategoryDTOToCategory(CategoryDTO categoryDTO) {
		if(categoryDTO == null)
			return null;
		
		Category category = new Category();
		category.setId(categoryDTO.getId());
		category.setName(categoryDTO.getName());
		
		return category;
	}
}
