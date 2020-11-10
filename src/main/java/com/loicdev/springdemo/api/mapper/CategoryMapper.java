package com.loicdev.springdemo.api.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import com.loicdev.springdemo.api.model.CategoryDTO;
import com.loicdev.springdemo.domain.Category;

@Mapper
public interface CategoryMapper {

	CategoryMapper INSTANCE = Mappers.getMapper(CategoryMapper.class);


    CategoryDTO categoryToCategoryDTO(Category category);
    
    Category CategoryDTOToCategory(CategoryDTO categoryDTO);
}
