# Roblox Outgoing packet-hook








I hope to elaborate upon the internals of networking of Roblox. Many things can be achieved by the intercepting Roblox packets. Roblox inherits each packet from and item class.
Furthermore, each packet type overrides the virtual function that writes the data for the respective packet to the bitstream.
In my outgoing packet logger, I place an int3 (interrupt3) breakpoint at the instruction that reads the write function from the virtual function table of the packet.
As shown in my previous post, this was found by placing a breakpoint and analyzing the return stack to the caller.

In my exception handler, I store the old write function location, which can be found at [eax+4], as shown by these images:

![image](https://github.com/Aegians/RBX-Packet-Hook/assets/69432633/4f26fb64-bf74-45b8-bc29-5cda793204fa)
![image](https://github.com/Aegians/RBX-Packet-Hook/assets/69432633/94f43bea-81ab-4a78-8989-1a1a5dc17532)

I then replace the eax register, the register now holding the write address, to my function hook and continue execution by incrementing the current instruction pointer and returning the status for continued execution.

Our hook, mocking the write function, now is passed the item instance, as well as the network stream, allowing us to alter the bitstream that holds that packet's data.

To not get caught by the game's integrity checker, I hook the job (US14116) that handles the stepping of the integrity checker.  Because the game heavily relies on the single threaded scheduler, we can restore the original bytes before firing the original job, and rehook them after.  Because of the single threaded model, when the scheduler re-loops, it will fire the packet job before reaching the integrity checker job; leaving us completely hidden.
