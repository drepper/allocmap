#include <cassert>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <list>
#include <type_traits>
#include <vector>
#include <ext/random>
#include <dwarf.h>
#include <error.h>
#include <fcntl.h>
#include <libelf.h>
#include <unistd.h>
#include <elfutils/libdwfl.h>

using namespace std::string_literals;

extern "C" void* xmalloc(size_t);
extern "C" void* xrealloc(void*, size_t);


namespace {
  // const char* boxes[16] = { " ", "▘", "▝", "▀", "▖", "▌", "▞", "▛",
  //			  "▗", "▚", "▐", "▜", "▄", "▙", "▟", "█" };
  // const char* hboxes[64] = { " ", "▀", " ", "▄", "█" };
  const char* fgcolors[40] = { // "39", "31", "32", "33", "34", "35", "36", "37",
			       "39", "38;5;1", "38;5;2", "38;5;3", "38;5;4", "38;5;5", "38;5;6", "38;5;7",
			       "38;5;8", "38;5;9", "38;5;10", "38;5;11", "38;5;12", "38;5;13", "38;5;14", "38;5;15",
			       "38;5;232", "38;5;233", "38;5;234", "38;5;235", "38;5;236", "38;5;237", "38;5;238", "38;5;239",
			       "38;5;240", "38;5;241", "38;5;242", "38;5;243", "38;5;244", "38;5;245", "38;5;246", "38;5;247",
			       "38;5;248", "38;5;249", "38;5;250", "38;5;251", "38;5;252", "38;5;253", "38;5;254", "38;5;255"
  };
  const char* bgcolors[40] = { //"49", "41", "42", "43", "44", "45", "46", "47",
			       "49", "48;5;1", "48;5;2", "48;5;3", "48;5;4", "48;5;5", "48;5;6", "48;5;7",
			       "48;5;8", "48;5;9", "48;5;10", "48;5;11", "48;5;12", "48;5;13", "48;5;14", "48;5;15",
			       "48;5;232", "48;5;233", "48;5;234", "48;5;235", "48;5;236", "48;5;237", "48;5;238", "48;5;239",
			       "48;5;240", "48;5;241", "48;5;242", "48;5;243", "48;5;244", "48;5;245", "48;5;246", "48;5;247",
			       "48;5;248", "48;5;249", "48;5;250", "48;5;251", "48;5;252", "48;5;253", "48;5;254", "48;5;255"
  };


  char* debuginfo_path;
  const Dwfl_Callbacks dwfl_callbacks = {
    /* .find_elf = */ dwfl_linux_proc_find_elf,
    /* .find_debuginfo = */ dwfl_standard_find_debuginfo,
    /* .section_address = */ dwfl_offline_section_address,
    /* .debuginfo_path = */ &debuginfo_path,
  };


  template <class Iterator>
  std::string textgrid_line(Iterator row1, Iterator row2, unsigned ncols, unsigned ncols1, unsigned ncols2)
  {
    std::string res;
    unsigned old_fgidx = 0;
    unsigned old_bgidx = 0;

    while (ncols1 > 0) {
      auto v1 = ncols1 > 0 ? (ncols1--, int(*row1++)) : 0;
      auto v2 = ncols2 > 0 ? (ncols2--, int(*row2++)) : 0;

      unsigned fgidx = v1 == 0 && v2 != 0 ? v2 : v1;
      unsigned bgidx = v1 != 0 && v2 != 0 && v1 != v2 ? v2 : 0;

      if (fgidx != old_fgidx || bgidx != old_bgidx) {
	res += "\e[";
	if (fgidx != old_fgidx) {
	  res += fgcolors[fgidx];
	  old_fgidx = fgidx;
	  if (bgidx != old_bgidx)
	    res += ';';
	}
	if (bgidx != old_bgidx) {
	  res += bgcolors[bgidx];
	  old_bgidx = bgidx;
	}
	res += 'm';
      }

      res += ((const char*[]) { " ", "▀", "▄", "▀", " ", "▀", "▄", "█" })[(v1!=0)+2*(v2!=0)+4*(v1==v2)];

      --ncols;
    }

    if (old_fgidx != 0) {
      res += "\e[39";
      if (old_bgidx != 0)
	res += ";49";
      res += "m";
    }
    while (ncols-- > 0)
      res += ' ';

    return res;
  }

  template <class Iterator>
  std::string textgrid_line(Iterator row1, Iterator row2, unsigned ncols)
  {
    return textgrid_line(row1, row2, ncols, ncols, ncols);
  }
} // anonymous namespace


template <class Iterator>
std::vector<std::string> textgrid(Iterator first, Iterator last, unsigned ncols)
{
  static_assert(std::is_same<std::random_access_iterator_tag,
			     typename std::iterator_traits<Iterator>::iterator_category>::value,
		"expect random iterator or raw pointer");

  auto nelems = std::distance(first, last);

  std::vector<std::string> res((nelems + 2 * ncols - 1) / (2 * ncols));
  auto wp = res.begin();

  while (first + 2 * ncols <= last) {
    *wp++ = std::move(textgrid_line(first, first + ncols, ncols));
    first += 2 * ncols;
  }

  if (first < last)
    *wp++ = std::move(textgrid_line(first, first + ncols, ncols,
				    std::min(ncols, unsigned(std::distance(first, last))),
				    std::max(0, int(std::distance(first, last) - ncols))));

  return res;
}


namespace {
  struct range {
    range(uint64_t start_, uint64_t end_, char r_, char w_, char x_, char p_, std::string&& name_)
      : start(start_), end(end_), r(r_), w(w_), x(x_), p(p_), name(std::move(name_)) { }

    uint64_t start;
    uint64_t end;
    char r;
    char w;
    char x;
    char p;
    bool any_present = false;
    std::string name;
  };

  std::list<range> getmaps(pid_t p)
  {
    auto fname = "/proc/"s + std::to_string(p) + "/maps";
    std::ifstream ifs(fname);
    if (! ifs.good())
      error(EXIT_FAILURE, 0, "cannot open %s", fname.c_str());

    std::list<range> res;
    while (! (ifs.peek(), ifs.eof())) {
      uint64_t start, end, tmp;
      char ch, r, w, x, p;
      std::string fname;
      ifs >> std::hex >> start;
      ifs >> ch;
      assert(ch == '-');
      ifs >> std::hex >> end;
      ifs >> r;
      ifs >> w;
      ifs >> x;
      ifs >> p;
      ifs >> std::hex >> tmp;
      ifs >> std::hex >> tmp;
      ifs >> ch;
      assert(ch == ':');
      ifs >> std::hex >> tmp;
      ifs >> std::dec >> tmp;
      while (ifs.peek() == ' ')
	ifs.get();
      std::getline(ifs, fname);

      res.emplace_back(start, end, r, w, x, p, std::move(fname));
    }

    return res;
  }


  const char* get_name_attr(Dwarf_Die* die)
  {
    const char* str = nullptr;
    if (dwarf_getattrs(die, [](Dwarf_Attribute* attrp, void* arg) -> int {
	  unsigned attr = dwarf_whatattr(attrp);
	  if (attr != DW_AT_name)
	    return DWARF_CB_OK;
	  unsigned form = dwarf_whatform(attrp);
	  assert(form == DW_FORM_strp || form == DW_FORM_string);
	  *(const char**) arg = dwarf_formstring(attrp);
	  return DWARF_CB_ABORT;
	}, &str, 0) == 1)
      return nullptr;
    return str;
  }

  Dwarf_Die* get_type_attr(Dwarf_Die* die, Dwarf_Die* res_mem)
  {
    if (dwarf_getattrs(die, [](Dwarf_Attribute* attrp, void* arg) -> int {
	  unsigned attr = dwarf_whatattr(attrp);
	  if (attr != DW_AT_type)
	    return DWARF_CB_OK;
	  unsigned form = dwarf_whatform(attrp);
	  assert(form == DW_FORM_ref4);
	  if (dwarf_formref_die(attrp, (Dwarf_Die*) arg) == nullptr)
	    return DWARF_CB_OK;
	  return DWARF_CB_ABORT;
	}, res_mem, 0) == 1)
      return nullptr;
    return res_mem;
  }

  size_t get_byte_size_attr(Dwarf_Die* die)
  {
    Dwarf_Word num;
    if (dwarf_getattrs(die, [](Dwarf_Attribute* attrp, void* arg) -> int {
	  unsigned attr = dwarf_whatattr(attrp);
	  if (attr != DW_AT_byte_size)
	    return DWARF_CB_OK;
	  unsigned form = dwarf_whatform(attrp);
	  assert(form == DW_FORM_data1 || form == DW_FORM_data2);
	  if (dwarf_formudata(attrp, (Dwarf_Word*) arg) != 0)
	    return DWARF_CB_OK;
	  return DWARF_CB_ABORT;
	}, &num, 0) == 1)
      return ~Dwarf_Word(0);
    return num;
  }

  size_t get_data_member_location_attr(Dwarf_Die* die)
  {
    Dwarf_Word num;
    if (dwarf_getattrs(die, [](Dwarf_Attribute* attrp, void* arg) -> int {
	  unsigned attr = dwarf_whatattr(attrp);
	  if (attr != DW_AT_data_member_location)
	    return DWARF_CB_OK;
	  unsigned form = dwarf_whatform(attrp);
	  assert(form == DW_FORM_data1 || form == DW_FORM_data2);
	  if (dwarf_formudata(attrp, (Dwarf_Word*) arg) != 0)
	    return DWARF_CB_OK;
	  return DWARF_CB_ABORT;
	}, &num, 0) == 1)
      return ~Dwarf_Word(0);
    return num;
  }

  size_t get_upper_bound_attr(Dwarf_Die* die)
  {
    Dwarf_Word num;
    if (dwarf_getattrs(die, [](Dwarf_Attribute* attrp, void* arg) -> int {
	  unsigned attr = dwarf_whatattr(attrp);
	  if (attr != DW_AT_upper_bound)
	    return DWARF_CB_OK;
	  unsigned form = dwarf_whatform(attrp);
	  assert(form == DW_FORM_data1);
	  if (dwarf_formudata(attrp, (Dwarf_Word*) arg) != 0)
	    return DWARF_CB_OK;
	  return DWARF_CB_ABORT;
	}, &num, 0) == 1)
      return ~Dwarf_Word(0);
    return num;
  }
} // anonymous namespace


int main(int argc, char* argv[])
{
  int opt;
  while ((opt = getopt(argc, argv, "h")) != -1)
    switch (opt) {
    case 'h':
      printf("%s [OPTION]... PID\n", argv[0]);
      return 0;
    default:
      return 1;
    }

  if (optind != argc - 1)
    printf("Usage: %s [OPTION]... PID\n", argv[0]);

  pid_t p = atoi(argv[optind]);

  int fdpm = open(("/proc/"s + std::to_string(p) + "/pagemap").c_str(), O_RDONLY);
  if (fdpm == -1)
    error(EXIT_FAILURE, errno, "cannot open pagemap");

  // int fdpf = open("/proc/kpageflags", O_RDONLY);

  Dwfl* dwfl = nullptr;
  dwfl = dwfl_begin(&dwfl_callbacks);

  dwfl_linux_proc_report(dwfl, p);
  dwfl_linux_proc_attach(dwfl, p, false);

  // find data type 'struct malloc_state'
  // find variable 'main_arena'

  struct main_arena_info_s {
    Dwfl_Module* mod = nullptr;
    Elf* elf = nullptr;
    bool have_addr = false;
    GElf_Addr addr;
    GElf_Addr bias = 0;
    uint8_t addrsize = 0;
    uint8_t long_double_size = 0;
  } main_arena_info;
  bool have_debuginfo = false;
  Dwarf_Die codie;
  ptrdiff_t pd = dwfl_getmodules(dwfl, [](Dwfl_Module *mod, void **, const char *name, Dwarf_Addr, void *arg) -> int {
      auto info = (main_arena_info_s*) arg;
      int res = DWARF_CB_OK;
      GElf_Addr bias;
      auto elf = dwfl_module_getelf(mod, &bias);
      if (elf != nullptr) {
	GElf_Ehdr ehdr_mem;
	GElf_Ehdr* ehdr = gelf_getehdr(elf, &ehdr_mem);
	for (unsigned i = 0; i < ehdr->e_phnum; ++i) {
	  GElf_Phdr phdr_mem;
	  GElf_Phdr* phdr = gelf_getphdr(elf, i, &phdr_mem);
	  if (phdr->p_type == PT_DYNAMIC) {
	    auto scn = gelf_offscn(elf, phdr->p_offset);
	    if (scn != nullptr) {
	      GElf_Shdr shdr_mem;
	      auto shdr = gelf_getshdr(scn, &shdr_mem);
	      auto data = elf_getdata(scn, nullptr);
	      if (shdr != nullptr && data != nullptr) {
		for (size_t j = 0; j < shdr->sh_size / shdr->sh_entsize; ++j) {
		  GElf_Dyn dyn_mem;
		  auto dyn = gelf_getdyn(data, j, &dyn_mem);
		  if (dyn->d_tag == DT_SONAME) {
		    auto soname = elf_strptr (elf, shdr->sh_link, dyn->d_un.d_val);
		    if (strcmp(soname, "libc.so.6") == 0) {
		      int symidx = 0;
		      const char* symname;
		      GElf_Word shndx;
		      GElf_Sym sym;
		      while ((symname = dwfl_module_getsym(mod, symidx, &sym, &shndx)) != nullptr) {
			if (strcmp(symname, "main_arena") == 0) {
			  info->have_addr = true;
			  info->addr = sym.st_value;
			  break;
			}
			++symidx;
		      }
		      info->mod = mod;
		      info->elf = elf;
		      info->bias = bias;
		      res = DWARF_CB_ABORT;
		    }
		    break;
		  }
		}
	      }
	    }
	    break;
	  }
	}
      }

      return res; },
    &main_arena_info, 0);
  if (pd != 0 && main_arena_info.mod != nullptr) {
    Dwarf_Addr dwarf_bias;
    auto dwarf = dwfl_module_getdwarf(main_arena_info.mod, &dwarf_bias);
    assert(dwarf != nullptr);

    size_t cuhl;
    Dwarf_Half version;
    Dwarf_Off abbroffset;
    uint8_t offsize;
    Dwarf_Off nextcu;
    Dwarf_Off offset = 0;
    while (1) {
      if (dwarf_next_unit(dwarf, offset, &nextcu, &cuhl, &version,
			  &abbroffset, &main_arena_info.addrsize, &offsize, nullptr, nullptr) != 0)
	break;

      offset += cuhl;

      Dwarf_Die cudie;
      dwarf_offdie(dwarf, offset, &cudie);
      int tag = dwarf_tag(&cudie);
      if (tag == DW_TAG_compile_unit) {
	const char* cuname = nullptr;
	if ((cuname = get_name_attr(&cudie)) != nullptr && strcmp(cuname, "malloc.c") == 0) {
	  // found malloc.c
	  if (dwarf_child(&cudie, &codie) == 0)
	    do {
	      const char* varname;
	      if (dwarf_tag(&codie) == DW_TAG_base_type
		  && (varname = get_name_attr(&codie)) != nullptr
		  && strcmp(varname, "long double") == 0) {
		main_arena_info.long_double_size = get_byte_size_attr(&codie);
	      } else if (dwarf_tag(&codie) == DW_TAG_variable
		  && (varname = get_name_attr(&codie)) != nullptr
		  && strcmp(varname, "main_arena") == 0) {
		have_debuginfo = true;

		if (! main_arena_info.have_addr) {
		  // Locate the symbol with the debug info.
		  dwarf_getattrs(&codie, [](Dwarf_Attribute* attrp, void* arg) -> int {
		      auto info = (main_arena_info_s*) arg;
		      unsigned attr = dwarf_whatattr(attrp);
		      if (attr != DW_AT_location)
			return DWARF_CB_OK;
		      unsigned form = dwarf_whatform(attrp);
		      assert(form == DW_FORM_exprloc);
		      Dwarf_Block block;
		      if (dwarf_formblock(attrp, &block) != 0)
			return DWARF_CB_ABORT;
		      if (block.length > 0) {
			assert(block.data[0] == DW_OP_addr);
			assert(block.length == 1u + info->addrsize);
			if (info->addrsize == 4)
			  info->addr = *(uint32_t*)(block.data+1);
			else if (info->addrsize == 8)
			  info->addr = *(uint64_t*)(block.data+1);
			else
			  return DWARF_CB_ABORT;
			info->have_addr = true;
			return DWARF_CB_ABORT;
		      }
		      return DWARF_CB_ABORT;
		    }, &main_arena_info, 0);
		}
		break;
	      }
	    } while (dwarf_siblingof(&codie, &codie) != 1);
	}
      }

      if (have_debuginfo)
	break;

      offset = nextcu;
    }
  }

  struct heap_info {
    uint64_t arena;
    uint64_t begin;
    uint64_t top_begin;
    uint64_t end;
  };
  std::vector<heap_info> heaps;

  size_t fastbins_offset = ~size_t(0);
  size_t fastbins_count = 0;
  size_t top_offset = ~size_t(0);
  // size_t last_remainder_offset = ~size_t(0);
  size_t bins_offset = ~size_t(0);
  size_t bins_count = ~size_t(0);
  size_t next_offset = ~size_t(0);
  // size_t next_free_offset = ~size_t(0);
  size_t system_mem_offset = ~size_t(0);
  // size_t pointer_size = 0;
  size_t malloc_chunk_size = ~size_t(0);
  // size_t mchunk_prev_size_offset = ~size_t(0);
  size_t mchunk_size_offset = ~size_t(0);
  size_t fd_offset = ~size_t(0);
  // size_t bk_offset = ~size_t(0);
  size_t fd_nextsize_offset = ~size_t(0);
  // size_t bk_nextsize_offset = ~size_t(0);
  size_t malloc_state_size = ~size_t(0);

  // Needed a couple of times.
  int memfd = open(("/proc/"s + std::to_string(p) + "/mem").c_str(), O_RDONLY);

  // Read the malloc state
  if (have_debuginfo) {
    Dwarf_Die malloc_state_die;
    if (get_type_attr(&codie, &malloc_state_die) != nullptr
	&& dwarf_tag(&malloc_state_die) == DW_TAG_structure_type
	&& strcmp(get_name_attr(&malloc_state_die), "malloc_state") == 0) {
      malloc_state_size = get_byte_size_attr(&malloc_state_die);
      Dwarf_Die member_die;
      if (dwarf_child(&malloc_state_die, &member_die) == 0) {
	do {
	  auto name = get_name_attr(&member_die);
	  auto memoff = get_data_member_location_attr(&member_die);
	  if (strcmp(name, "fastbinsY") == 0) {
	    fastbins_offset = memoff;
	    Dwarf_Die fastbins_die;
	    if (get_type_attr(&member_die, &fastbins_die) != nullptr
		&& dwarf_tag(&fastbins_die) == DW_TAG_array_type) {
	      Dwarf_Die array_die;
	      if (dwarf_child(&fastbins_die, &array_die) == 0
		  && dwarf_tag(&array_die) == DW_TAG_subrange_type) {
		fastbins_count = get_upper_bound_attr(&array_die) + 1;
		Dwarf_Die arrayel_die;
		if (get_type_attr(&fastbins_die, &arrayel_die) != nullptr) {
		  if (dwarf_tag(&arrayel_die) == DW_TAG_typedef
		      && get_type_attr(&arrayel_die, &arrayel_die) == nullptr)
		    assert("mfastbinptr type fetch failed");

		  assert(dwarf_tag(&arrayel_die) == DW_TAG_pointer_type);
		  // pointer_size = get_byte_size_attr(&arrayel_die);

		  Dwarf_Die malloc_chunk_die;
		  if (get_type_attr(&arrayel_die, &malloc_chunk_die) != nullptr
		      && dwarf_tag(&malloc_chunk_die) == DW_TAG_structure_type) {
		    malloc_chunk_size = get_byte_size_attr(&malloc_chunk_die);

		    Dwarf_Die mchunkel_die;
		    if (dwarf_child(&malloc_chunk_die, &mchunkel_die) == 0) {

		      do {
			auto mcname = get_name_attr(&mchunkel_die);
			auto mcoff = get_data_member_location_attr(&mchunkel_die);
			if (strcmp(mcname, "mchunk_size") == 0)
			  mchunk_size_offset = mcoff;
			// else if (strcmp(mcname, "mchunk_prev_size") == 0)
			//   mchunk_prev_size_offset = mcoff;
			else if (strcmp(mcname, "fd") == 0)
			  fd_offset = mcoff;
			// else if (strcmp(mcname, "bk") == 0)
			//   bk_offset = mcoff;
			else if (strcmp(mcname, "fd_nextsize") == 0)
			  fd_nextsize_offset = mcoff;
			// else if (strcmp(mcname, "bk_nextsize") == 0)
			//   bk_nextsize_offset = mcoff;
		      } while (dwarf_siblingof(&mchunkel_die, &mchunkel_die) != 1);
		    }
		  }
		}
	      }
	    }
	  } else if (strcmp(name, "top") == 0) {
	    top_offset = memoff;
	  // } else if (strcmp(name, "last_remainder") == 0) {
	  //   last_remainder_offset = memoff;
	  } else if (strcmp(name, "bins") == 0) {
	    bins_offset = memoff;
	    Dwarf_Die bins_die;
	    if (get_type_attr(&member_die, &bins_die) != nullptr
		&& dwarf_tag(&bins_die) == DW_TAG_array_type) {
	      Dwarf_Die array_die;
	      if (dwarf_child(&bins_die, &array_die) == 0
		  && dwarf_tag(&array_die) == DW_TAG_subrange_type) {
		bins_count = get_upper_bound_attr(&array_die) + 1;
	      }
	    }
	  } else if (strcmp(name, "next") == 0) {
	    next_offset = memoff;
	  // } else if (strcmp(name, "next_free") == 0) {
	  //   next_free_offset = memoff;
	  } else if (strcmp(name, "system_mem") == 0) {
	    system_mem_offset = memoff;
	  }
	} while (dwarf_siblingof(&member_die, &member_die) != 1);

	if (memfd != -1) {
	  auto arena_addr = main_arena_info.addr;

	next:
	  uint8_t *arena_mem = (uint8_t*) xmalloc(malloc_state_size);
	  if (size_t(pread(memfd, arena_mem, malloc_state_size, main_arena_info.addr)) == malloc_state_size) {
	    //for (int u=0;u<100;++u)printf(" %hhx", arena_mem[u]);putchar('\n');

	    assert(top_offset + main_arena_info.addrsize <= malloc_state_size);
	    uint64_t top;
	    uint64_t system_mem;
	    if (main_arena_info.addrsize == 8) {
	      top = *(uint64_t*)(arena_mem + top_offset);
	      system_mem = *(uint64_t*)(arena_mem + system_mem_offset);
	    } else {
	      top = *(uint32_t*)(arena_mem + top_offset);
	      system_mem = *(uint32_t*)(arena_mem + system_mem_offset);
	    }

	    char top_chunk[fd_nextsize_offset];
	    if (size_t(pread(memfd, top_chunk, fd_nextsize_offset, top)) == fd_nextsize_offset) {
	      uint64_t top_size;
	      if (main_arena_info.addrsize == 8)
		top_size = *(uint64_t*)(top_chunk + mchunk_size_offset) & ~(uint64_t)7;
	      else
		top_size = *(uint32_t*)(top_chunk + mchunk_size_offset) & ~(uint32_t)7;

	      heaps.emplace_back(heap_info{main_arena_info.addr, top + top_size - system_mem, top, top + top_size});
	    }

	    if (main_arena_info.addrsize == 8) {
	      arena_addr = *(uint64_t*)(arena_mem + next_offset);
	      if (arena_addr != main_arena_info.addr)
		goto next;
	    } else{
	      arena_addr = *(uint32_t*)(arena_mem + next_offset);
	      if (arena_addr != main_arena_info.addr)
		goto next;
	    }
	  }
	  free(arena_mem);
	}
      }
    }
  }

  enum class pmstate : uint8_t {
    unknown = 0,
    swapped,
    anon4k,
    file4k,
    topchunk,
    topchunk_notpresent,

    notpresent = 20
  };

  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::unknown)] << "m████\e[0m   unknown\n";
  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::swapped)] << "m████\e[0m   swapped\n";
  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::anon4k)] << "m████\e[0m   anonymous\n";
  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::file4k)] << "m████\e[0m   file backed\n";
  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::topchunk)] << "m████\e[0m   arena top chunk\n";
  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::topchunk_notpresent)] << "m████\e[0m   arena top chunk not present\n";
  std::cout << "    \e[" << fgcolors[uint8_t(pmstate::notpresent)] << "m████\e[0m   not present\n";

  auto ps = sysconf(_SC_PAGESIZE);
  auto maps = getmaps(p);
  for (auto& m : maps) {
    const auto npages = (m.end - m.start) / ps;
    std::vector<uint64_t> pm(npages);
    std::vector<pmstate> v(npages);
    auto n = size_t(pread(fdpm, pm.data(), npages * sizeof(uint64_t), m.start / ps * sizeof(uint64_t)));
    if (n != npages * sizeof(uint64_t)) {
      if (n != 0 || m.name != "[vsyscall]"s)
	error(EXIT_FAILURE, 0, "incomplete pagemap read");
      std::fill(v.begin(), v.end(), pmstate::unknown);
    } else {
      constexpr auto pm_present = uint64_t(1) << 63;
      constexpr auto pm_swapped = uint64_t(1) << 62;
      constexpr auto pm_shared = uint64_t(1) << 61;

      std::transform(pm.begin(), pm.end(), v.begin(),
		     [&m](uint64_t pm) {
		       if ((pm & pm_present) == 0) return pmstate::notpresent;
		       m.any_present = true;
		       if (pm & pm_swapped) return pmstate::swapped;
		       if (pm & pm_shared) {
			 return pmstate::file4k;
		       } else {
			 return pmstate::anon4k;
		       }
		     });

      if (! m.any_present)
	continue;
    }

    for (const auto& h : heaps)
      if (h.top_begin >= m.start && h.top_begin < m.end) {
	uint64_t round_from = (h.top_begin + ps - 1) & ~(ps - 1);
	assert(h.end % ps == 0);

	size_t fromidx = (round_from - m.start) / ps;
	assert(fromidx <= npages);
	size_t toidx = (h.end - m.start) / ps;
	assert(toidx <= npages);
	for (size_t j = fromidx; j < toidx; ++j)
	  if (v[j] == pmstate::notpresent)
	    v[j] = pmstate::topchunk_notpresent;
	  else
	    v[j] = pmstate::topchunk;
	break;
      }

    std::cout << (m.name.length() == 0 ? "<anonymous>"s : m.name) << " [" << m.r << m.w << m.x << m.p << "]\n";

    const unsigned npagecols = 80;
    auto addr = m.start;
    auto p = textgrid(std::begin(v), std::end(v), npagecols);
    for (auto& s : p) {
      std::cout << "  " << std::setw(16) << std::setfill('.') << std::hex << addr << "  " << s << std::endl;
      addr += npagecols * 2 * ps;
    }
  }

  if (heaps.size() > 0) {
    std::cout << std::endl;

    std::cout << "    \e[" << fgcolors[uint8_t(pmstate::notpresent)] << "m████\e[0m   0 of 8 chunks used\n";
    for (size_t ii = 1; ii <= 8; ++ii)
      std::cout << "    \e[" << fgcolors[24+ii] << "m████\e[0m   " << ii << " of 8 chunks used\n";

    uint8_t *arena_p = (uint8_t*) xmalloc(malloc_state_size);

    for (const auto&h : heaps) {
      size_t malloc_alignment = 2 * main_arena_info.addrsize;
      if (main_arena_info.long_double_size > malloc_alignment)
	malloc_alignment = main_arena_info.long_double_size;
      size_t malloc_align_mask = malloc_alignment - 1;
      size_t minsize = (fd_nextsize_offset + malloc_align_mask) & ~malloc_align_mask;
      size_t nchunks = (h.end - h.begin) / malloc_alignment;
      size_t nfillcnt = (nchunks + 7) / 8;
      size_t nchunkcols = 80;
      std::vector<uint8_t> filled(nfillcnt);

      // There is not list of used memory, only the freed data is
      // accessible.  Therefore the default value is that all blocks
      // are used and substract one for every free chunk.
      std::fill(filled.begin(), filled.end(), 8);

      auto clear = [&filled,&h,malloc_alignment](uint64_t addr){
	auto idx = (addr-h.begin)/malloc_alignment/8;
	--filled[idx];
	// std::cout << "clear " << idx << std::endl;
      };

      assert((h.top_begin + fd_offset) % malloc_alignment == 0);
      for (auto a = h.top_begin + fd_offset; a < h.end; a += malloc_alignment)
	clear(a);

      printf("arena @%llx\n", (unsigned long long) h.arena);
      if (size_t(pread(memfd, arena_p, malloc_state_size, h.arena)) == malloc_state_size) {
	for (size_t i = 0; i < fastbins_count; ++i) {
	  uint64_t binptr;
	  if (main_arena_info.addrsize == 8)
	    binptr = ((uint64_t*)(arena_p + fastbins_offset))[i];
	  else
	    binptr = ((uint32_t*)(arena_p + fastbins_offset))[i];
	  while (binptr != 0) {
	    if (binptr < h.begin || binptr >= h.end) {
	      std::cout << "invalid binptr in binfastsY[" << i << "] = " << binptr << std::endl;
	      break;
	    }

	    char chunk[malloc_chunk_size];
	    if (size_t(pread(memfd, chunk, malloc_chunk_size, binptr)) != malloc_chunk_size)
	      break;

	    uint64_t size;
	    if (main_arena_info.addrsize == 8)
	      size = *(uint64_t*)(chunk + mchunk_size_offset) & ~uint64_t(7);
	    else
	      size = *(uint32_t*)(chunk + mchunk_size_offset) & ~uint32_t(7);
	    assert(size >= minsize);
	    assert((size & malloc_align_mask) == 0);
	    uint64_t addr = binptr;
	    assert((addr & malloc_align_mask) == 0);
	    for (; addr < binptr + size; addr += malloc_alignment)
	      clear(addr);

	    if (main_arena_info.addrsize == 8)
	      binptr = *(uint64_t*)(chunk + fd_offset);
	    else
	      binptr = *(uint32_t*)(chunk + fd_offset);
	  }
	}

	for (size_t i = 0; i < bins_count; i += 2) {
	  uint64_t binaddr;
	  uint64_t binptr;
	  if (main_arena_info.addrsize == 8) {
	    binaddr = h.arena + bins_offset + i * sizeof(uint64_t);
	    binptr = ((uint64_t*)(arena_p + bins_offset))[i];
	  } else {
	    binaddr = h.arena + bins_offset + i * sizeof(uint32_t);
	    binptr = ((uint32_t*)(arena_p + bins_offset))[i];
	  }
	  while (binptr + fd_offset != uint64_t(binaddr)) {
	    if (binptr < h.begin || binptr >= h.end) {
	      std::cout << "invalid binptr in bins[" << i << "] = " << binptr << std::endl;
	      break;
	    }

	    char chunk[malloc_chunk_size];
	    if (size_t(pread(memfd, chunk, malloc_chunk_size, binptr)) != malloc_chunk_size)
	      break;

	    uint64_t size;
	    if (main_arena_info.addrsize == 8)
	      size = *(uint64_t*)(chunk + mchunk_size_offset) & ~uint64_t(7);
	    else
	      size = *(uint32_t*)(chunk + mchunk_size_offset) & ~uint32_t(7);
	    assert(size >= minsize);
	    assert((size & malloc_align_mask) == 0);
	    uint64_t addr = binptr;
	    assert((addr & malloc_align_mask) == 0);
	    for (; addr < binptr + size; addr += malloc_alignment)
	      clear(addr);

	    if (main_arena_info.addrsize == 8)
	      binptr = *(uint64_t*)(chunk + fd_offset);
	    else
	      binptr = *(uint32_t*)(chunk + fd_offset);
	  }
	}
      }

      std::transform(filled.begin(), filled.end(), filled.begin(), [](uint8_t v){ return v ? 24 + v : 20; });

      auto addr = h.begin;
      auto p = textgrid(std::begin(filled), std::end(filled), nchunkcols);
      for (auto& s : p) {
	std::cout << "  " << std::setw(16) << std::setfill('.') << std::hex << addr << "  " << s << std::endl;
	addr += nchunkcols * 2 * malloc_chunk_size * 8;
      }
    }

    free(arena_p);
  }
}
