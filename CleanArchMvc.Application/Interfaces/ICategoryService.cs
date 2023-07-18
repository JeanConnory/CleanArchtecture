using CleanArchMvc.Application.DTOs;
using CleanArchMvc.Domain.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CleanArchMvc.Application.Interfaces
{
	public interface ICategoryService
	{
		Task<IEnumerable<CategoryDTO>> GetCategories();
		Task<CategoryDTO> GetById(int? id);
		Task Add(CategoryDTO categoryDto);
		Task Update(CategoryDTO categoryDto);
		Task Remove(int? id);
	}
}
