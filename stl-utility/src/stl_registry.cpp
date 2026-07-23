#include "stl_registry.h"

namespace stl_utility
{

void register_stl_string_descriptors(std::vector<const stl_type_descriptor_t *> *out);
void register_stl_shared_ptr_descriptors(std::vector<const stl_type_descriptor_t *> *out);
void register_stl_vector_descriptors(std::vector<const stl_type_descriptor_t *> *out);
void register_stl_unique_ptr_descriptors(std::vector<const stl_type_descriptor_t *> *out);
void register_stl_tree_descriptors(std::vector<const stl_type_descriptor_t *> *out);
void register_stl_unordered_map_descriptors(std::vector<const stl_type_descriptor_t *> *out);

namespace
{

std::vector<const stl_type_descriptor_t *> build_registry()
{
  std::vector<const stl_type_descriptor_t *> result;
  register_stl_string_descriptors(&result);
  register_stl_shared_ptr_descriptors(&result);
  register_stl_vector_descriptors(&result);
  register_stl_unique_ptr_descriptors(&result);
  register_stl_tree_descriptors(&result);
  register_stl_unordered_map_descriptors(&result);
  return result;
}

} // namespace

const std::vector<const stl_type_descriptor_t *> &get_stl_descriptor_registry()
{
  static const std::vector<const stl_type_descriptor_t *> registry = build_registry();
  return registry;
}

} // namespace stl_utility
