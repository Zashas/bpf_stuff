#include <inttypes.h>
#include <time.h>

extern uint32_t mono_real_diff_ns()
{
	struct timespec mono, real;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	if (mono.tv_nsec > real.tv_nsec)
		return (uint32_t) (1000000000 - mono.tv_nsec + real.tv_nsec);
	
	return (uint32_t) (real.tv_nsec - mono.tv_nsec);
}

extern uint32_t mono_real_diff_sec()
{
	struct timespec mono, real;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);

	if (mono.tv_nsec > real.tv_nsec)
		return (uint32_t) (real.tv_sec - mono.tv_sec - 1);

	return (uint32_t) (real.tv_sec - mono.tv_sec);
}
