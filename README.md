# Samsara

The main goal of Samsara is to implement a software approach that can take full advantage of the latest hardware features in commodity processors to record and replay memory access interleaving efficiently without introducing any hardware modifications.

## What is Samsara?

Deterministic replay, which provides the ability to travel backward in time and reconstruct the past execution flow of a
multiprocessor system, has many prominent applications. Prior research in this area can be classified into two categories:
hardware-only schemes and software-only schemes. While hardware-only schemes deliver high performance, they require significant
modifications to the existing hardware. In contrast, software-only schemes work on commodity hardware, but suffer from excessive
performance overhead and huge logs. In this article, we present the design and implementation of a novel system, Samsara, which
uses the hardware-assisted virtualization (HAV) extensions to achieve efficient deterministic replay without requiring any hardware
modification. Unlike prior software schemes which trace every single memory access to record interleaving, Samsara leverages HAV
on commodity processors to track the read-set and write-set for implementing a chunk-based recording scheme in software. By doing
so, we avoid all memory access detections, which is a major source of overhead in prior works.


To read more about the Samsara,check out [the project page](http://zhenxiao.com/replay/).
