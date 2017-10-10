CPP_FILES := $(wildcard source/*.cpp)
OBJ_FILES := $(addprefix obj/,$(notdir $(CPP_FILES:.cpp=.o)))
LD_FLAGS := -lpcap
CC_FLAGS := -I include/

mydump: $(OBJ_FILES)
	g++ -o $@ $^ $(LD_FLAGS)

obj/%.o: source/%.cpp
	g++ $(CC_FLAGS) -c -o $@ $<

clean :
	\rm -fr obj/*
	\rm -fr mydump
	\rm -fr *~
