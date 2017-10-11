// Written by Ulrich Drepper <drepper@gmail.com>.
// Copyright © 2017
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


namespace {
  const char* colors[40] = { "9", "8;5;1", "8;5;2", "8;5;3", "8;5;4", "8;5;5", "8;5;6", "8;5;7",
			     "8;5;8", "8;5;9", "8;5;10", "8;5;11", "8;5;12", "8;5;13", "8;5;14", "8;5;15",
			     "8;5;232", "8;5;233", "8;5;234", "8;5;235", "8;5;236", "8;5;237", "8;5;238", "8;5;239",
			     "8;5;240", "8;5;241", "8;5;242", "8;5;243", "8;5;244", "8;5;245", "8;5;246", "8;5;247",
			     "8;5;248", "8;5;249", "8;5;250", "8;5;251", "8;5;252", "8;5;253", "8;5;254", "8;5;255"
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
	  res += "3"s + colors[fgidx];
	  old_fgidx = fgidx;
	  if (bgidx != old_bgidx)
	    res += ';';
	}
	if (bgidx != old_bgidx) {
	  res += "4"s + colors[bgidx];
	  old_bgidx = bgidx;
	}
	res += 'm';
      }

      res += ((const char*[]) { " ", "▀", "▄", "▀", " ", "▀", "▄", "█" })[(v1!=0)+2*(v2!=0)+4*(v1==v2)];

      --ncols;
    }

    if (old_fgidx != 0)
      res += "\e[0m";
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
      ifs >> r >> w >> x >> p;
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


  struct addraccess {
    addraccess(int s) : size(s) {}
    uint64_t operator()(const uint8_t* p, size_t off) const {
      return size == 8 ? *(const uint64_t*)(p + off) : *(const uint32_t*)(p + off);
    }
    uint64_t operator()(const uint8_t* p, size_t off, size_t idx) const {
      return size == 8 ? ((const uint64_t*)(p + off))[idx] : ((const uint32_t*)(p + off))[idx];
    }
  private:
    const int size;
  };


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
      std::cout << argv[0] << " [OPTION]... PID\n";
      return 0;
    default:
      return 1;
    }

  if (optind != argc - 1) {
    std::cout << argv[0] << " [OPTION]... PID\n";
    return 1;
  }

  pid_t p = atoi(argv[optind]);

  int fdpm = open(("/proc/"s + std::to_string(p) + "/pagemap").c_str(), O_RDONLY);
  if (fdpm == -1)
    error(EXIT_FAILURE, errno, "cannot open pagemap");

  int fdpf = open("/proc/kpageflags", O_RDONLY);

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

  addraccess aa(main_arena_info.addrsize);

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
	  auto arena_mem = new uint8_t[malloc_state_size];
	  if (size_t(pread(memfd, arena_mem, malloc_state_size, main_arena_info.addr)) == malloc_state_size) {
	    assert(top_offset + main_arena_info.addrsize <= malloc_state_size);
	    uint64_t top;
	    uint64_t system_mem;
	    top = aa(arena_mem, top_offset);
	    system_mem = aa(arena_mem, system_mem_offset);

	    uint8_t top_chunk[fd_nextsize_offset];
	    if (size_t(pread(memfd, top_chunk, fd_nextsize_offset, top)) == fd_nextsize_offset) {
	      uint64_t top_size = aa(top_chunk, mchunk_size_offset) & ~(uint64_t)7;

	      heaps.emplace_back(heap_info{main_arena_info.addr, top + top_size - system_mem, top, top + top_size});
	    }

	    arena_addr = aa(arena_mem, next_offset);
	    if (arena_addr != main_arena_info.addr)
	      goto next;
	  }
	  delete[] arena_mem;
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
    anon2M,
    anon1G = 8,
    file2M = 12,
    file1G = 13,

    notpresent = 20
  };

  std::cout << "    \e[3" << colors[uint8_t(pmstate::unknown)] << "m████\e[0m   unknown\n";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::swapped)] << "m████\e[0m   swapped\n";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::anon4k)] << "m████\e[0m   4k anonymous  ";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::anon2M)] << "m████\e[0m   2M anonymous  ";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::anon1G)] << "m████\e[0m   1G anonymous\n";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::file4k)] << "m████\e[0m   4k file backed";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::file2M)] << "m████\e[0m   2M file backed";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::file1G)] << "m████\e[0m   1G file backed\n";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::topchunk)] << "m████\e[0m   arena top chunk\n";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::topchunk_notpresent)] << "m████\e[0m   arena top chunk not present\n";
  std::cout << "    \e[3" << colors[uint8_t(pmstate::notpresent)] << "m████\e[0m   not present\n";

  auto ps = sysconf(_SC_PAGESIZE);
  auto maps = getmaps(p);
  for (auto& m : maps) {
    const auto npages = (m.end - m.start) / ps;
    std::vector<uint64_t> pm(npages);
    std::vector<pmstate> v(npages);
    auto n = size_t(pread(fdpm, pm.data(), npages * sizeof(uint64_t), m.start / ps * sizeof(uint64_t)));
    if (n != npages * sizeof(uint64_t)) {
      if (n != 0 || m.name != "[vsyscall]"s)
	error(EXIT_FAILURE, errno, "incomplete pagemap read");
      std::fill(v.begin(), v.end(), pmstate::unknown);
    } else {
      constexpr auto pm_present = uint64_t(1) << 63;
      constexpr auto pm_swapped = uint64_t(1) << 62;
      constexpr auto pm_shared = uint64_t(1) << 61;

      std::transform(pm.begin(), pm.end(), v.begin(),
		     [&m](uint64_t pm) {
		       if (pm & pm_swapped) return pmstate::swapped;
		       if ((pm & pm_present) == 0) return pmstate::notpresent;
		       m.any_present = true;
		       if (pm & pm_shared) {
			 return pmstate::file4k;
		       } else {
			 return pmstate::anon4k;
		       }
		     });

      if (! m.any_present && m.r == '-')
	continue;

      if (fdpf != -1) {
	std::vector<uint64_t> pf(npages);
	std::fill(pf.begin(), pf.end(), 0);

	bool has_pfn = false;
	size_t first_range = 0;
	size_t first_pfn = 0;
	for (size_t i = 0; i < npages; ++i) {
	  if (has_pfn && (pm[i] & pm_present) && (pm[i] & ((uint64_t(1) << 55) - 1)) == first_pfn + (i - first_range))
	    continue;

	  if (has_pfn) {
	    n = size_t(pread(fdpf, pf.data() + first_range, (i - first_range) * sizeof(uint64_t), first_pfn * sizeof(uint64_t)));
	    if (n < (i - first_range) * sizeof(uint64_t))
	      error(EXIT_FAILURE, errno, "incomplete pageflags read");
	  }
	  if (pm[i] & pm_present) {
	    first_range = i;
	    first_pfn = pm[i] & ((uint64_t(1) << 55) -1);
	    has_pfn = true;
	  } else
	    has_pfn = false;
	}
	if (has_pfn) {
	  n = size_t(pread(fdpf, pf.data() + first_range, (npages - first_range) * sizeof(uint64_t), first_pfn * sizeof(uint64_t)));
	  if (n < (npages - first_range) * sizeof(uint64_t))
	    error(EXIT_FAILURE, errno, "incomplete pageflags read");
	}

	constexpr uint64_t pf_compound_head = uint64_t(1) << 15;
	constexpr uint64_t pf_compound_tail = uint64_t(1) << 16;
	ssize_t last_head = -1;
	for (ssize_t i = 0; i < ssize_t(npages); ++i)
	  if (pf[i] & pf_compound_head) {
	    if (last_head != -1)
	      error(EXIT_FAILURE, 0, "compound head without tail");
	    if (pf[i] & pf_compound_tail)
	      error(EXIT_FAILURE, 0, "compound head together with tail");
	    last_head = i;
	  } else if (pf[i] & pf_compound_tail) {
	    if (last_head == -1)
	      error(EXIT_FAILURE, 0, "compound tail without head");
	    auto nlarge = i + 1 - last_head;
	    bool is_2M = false;
	    if (nlarge*ps == 2*1024*1024)
	      is_2M = true;
	    else if (nlarge*ps != 1*1024*1024*1024)
	      error(EXIT_FAILURE, 0, "strange page size %zu", nlarge*ps);

	    for (auto j = last_head; j <= i; ++j)
	      if (v[j] == pmstate::file4k) {
		v[j] = is_2M ? pmstate::file2M : pmstate::file1G;
	      } else if (v[j] == pmstate::anon4k) {
		v[j] = is_2M ? pmstate::anon2M : pmstate::anon1G;
	      } else
		error(EXIT_FAILURE, 0, "huge page for mapping %d", int(v[j]));
	  }

	close(fdpf);
      }
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

    std::cout << "    \e[3" << colors[uint8_t(pmstate::notpresent)] << "m████\e[0m   0 of 8 chunks used\n";
    for (size_t ii = 1; ii <= 8; ++ii)
      std::cout << "    \e[3" << colors[24+ii] << "m████\e[0m   " << ii << " of 8 chunks used\n";

    auto arena_p = new uint8_t[malloc_state_size];

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

      auto clear = [&filled,begin=h.begin,malloc_alignment](uint64_t addr){
	auto idx = (addr - begin) / malloc_alignment / 8;
	--filled[idx];
	// std::cout << "clear " << idx << std::endl;
      };

      assert((h.top_begin + fd_offset) % malloc_alignment == 0);
      for (auto a = h.top_begin + fd_offset; a < h.end; a += malloc_alignment)
	clear(a);

      std::cout << "arena @0x" << std::hex << h.arena << std::endl;
      if (size_t(pread(memfd, arena_p, malloc_state_size, h.arena)) == malloc_state_size) {
	for (size_t i = 0; i < fastbins_count; ++i) {
	  uint64_t binptr;
	  binptr = aa(arena_p, fastbins_offset, i);
	  while (binptr != 0) {
	    if (binptr < h.begin || binptr >= h.end) {
	      std::cout << "invalid binptr in binfastsY[" << i << "] = " << binptr << std::endl;
	      break;
	    }

	    uint8_t chunk[malloc_chunk_size];
	    if (size_t(pread(memfd, chunk, malloc_chunk_size, binptr)) != malloc_chunk_size)
	      break;

	    uint64_t size = aa(chunk, mchunk_size_offset) & ~uint64_t(7);
	    assert(size >= minsize);
	    assert((size & malloc_align_mask) == 0);
	    uint64_t addr = binptr;
	    assert((addr & malloc_align_mask) == 0);
	    for (; addr < binptr + size; addr += malloc_alignment)
	      clear(addr);

	    binptr = aa(chunk, fd_offset);
	  }
	}

	for (size_t i = 0; i < bins_count; i += 2) {
	  uint64_t binaddr = h.arena + bins_offset + i * main_arena_info.addrsize;
	  uint64_t binptr = aa(arena_p, bins_offset, i);
	  while (binptr + fd_offset != uint64_t(binaddr)) {
	    if (binptr < h.begin || binptr >= h.end) {
	      std::cout << "invalid binptr in bins[" << i << "] = " << binptr << std::endl;
	      break;
	    }

	    uint8_t chunk[malloc_chunk_size];
	    if (size_t(pread(memfd, chunk, malloc_chunk_size, binptr)) != malloc_chunk_size)
	      break;

	    uint64_t size = aa(chunk, mchunk_size_offset) & ~uint64_t(7);
	    assert(size >= minsize);
	    assert((size & malloc_align_mask) == 0);
	    uint64_t addr = binptr;
	    assert((addr & malloc_align_mask) == 0);
	    for (; addr < binptr + size; addr += malloc_alignment)
	      clear(addr);

	    binptr = aa(chunk, fd_offset);
	  }
	}
      }

      std::transform(filled.begin(), filled.end(), filled.begin(), [](uint8_t v){ return v ? 24 + v : 20; });

      auto addr = h.begin;
      auto p = textgrid(std::begin(filled), std::end(filled), nchunkcols);
      for (auto& s : p) {
	std::cout << "  " << std::setw(16) << std::setfill('.') << std::hex << addr << "  " << s << std::endl;
	addr += nchunkcols * 2 * malloc_alignment * 8;
      }
    }

    delete[] arena_p;
  }
}
