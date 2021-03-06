module bitcoin_hash (
	input	logic 	clk, reset_n, start,
	input	logic		[15:0] message_addr, output_addr,
	output logic	done, mem_clk, mem_we,
	output logic 	[15:0] mem_addr,
	output logic	[31:0] mem_write_data,
	input logic 	[31:0] mem_read_data
);

assign mem_clk = clk;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

parameter NUM_NONCES = 16;

logic	[31:0] fh0, fh1, fh2, fh3, fh4, fh5, fh6, fh7;
logic	[31:0] a, b, c, d, e, f, g, h;
logic	[31:0] h0[NUM_NONCES];
logic	[31:0] h1[NUM_NONCES];
logic	[31:0] h2[NUM_NONCES];
logic	[31:0] h3[NUM_NONCES];
logic	[31:0] h4[NUM_NONCES];
logic	[31:0] h5[NUM_NONCES];
logic	[31:0] h6[NUM_NONCES];
logic	[31:0] h7[NUM_NONCES];

logic	[7:0]	tIndex;			// index to track number of expand iters
logic	[6:0]	readOffset;		// value to track read addr offset
logic	[6:0]	writeOffset;	// value to track write addr offset
logic	[6:0]	nonceIndex;		// which nonce are we on
logic			b2Done;
logic	[31:0] w[16];			// 16 elelment word array
logic	[4:0] i;					// index for for loop
/*logic [31:0] w_15, w_14, w_13, h0_naught, h0_one, h0_two, h0_3, h0_4, h0_5, h0_6, h0_7, h0_8, h0_9, h0_10;
logic [31:0] h0_11, h0_12, h0_13, h0_14, h0_15;

assign w_15 = w[15];
assign w_14 = w[14];
assign w_13 = w[13];
assign h0_naught = h0[0];
assign h0_one = h0[1];
assign h0_two = h0[2];
assign h0_3 = h0[3];
assign h0_4 = h0[4];
assign h0_5 = h0[5];
assign h0_6 = h0[6];
assign h0_7 = h0[7];
assign h0_8 = h0[8];
assign h0_9 = h0[9];
assign h0_10 = h0[10];
assign h0_11 = h0[11];
assign h0_12 = h0[12];
assign h0_13 = h0[13];
assign h0_14 = h0[14];
assign h0_15 = h0[15];*/

//states
enum logic [4:0] {IDLE=5'b00000, PRIME_ADDR=5'b00001, FIRST_READ=5'b00010, FIRST_16=5'b00011, 
						NEXT_48=5'b00100, FINALIZE_HASH=5'b00101, WAIT=5'b00110, BEFORE_NONCE=5'b00111, 
						NONCE=5'b01000, AFTER_NONCE=5'b01001, WRITE=5'b01010, DONE = 5'b01111,
						BLOCK2_INIT=5'b11111,BLOCK2_WORD_EXP=5'b10000,HASH2_INIT=5'b10001,HASH2_WORD_EXP=5'b10010,
						NONCE_BLOCK_2_WAIT=5'b10011, START_BLOCK_3=5'b10100, STALL_BLOCK_3=5'b10101, 
						EXP_BLOCK_3=5'b10110, HASH_BLOCK_3=5'b11000, AFTER_BLOCK_3=5'b11001, WRITE_NONCES = 5'b11010} state;



// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction


function logic [31:0] rrot(input logic [31:0] x,
                                  input logic [7:0] r);
begin
    rrot = (x >> r) | (x << (32-r));
end
endfunction

function logic [31:0] wtnew;
	logic [31:0] s0, s1;
	s0 = rrot(w[1],7)^rrot(w[1],18)^(w[1]>>3);
	s1 = rrot(w[14],17)^rrot(w[14],19)^(w[14]>>10);
	wtnew = w[0] + s0 + w[9] + s1;
endfunction

	
always @(posedge clk, negedge reset_n) begin

	// when reset is high, reset Index values and initialize hashes to correct vals
	if( !reset_n ) begin 
		//wIndex = 'b0;
		tIndex = 8'b0;
		b2Done = 1'b0;
		readOffset = 7'b0;
		writeOffset = 7'b0;
		nonceIndex = 7'b0;
		
		fh0 = 32'h6a09e667;
		fh1 = 32'hbb67ae85;
		fh2 = 32'h3c6ef372;
		fh3 = 32'ha54ff53a;
		fh4 = 32'h510e527f;
		fh5 = 32'h9b05688c;
		fh6 = 32'h1f83d9ab;
		fh7 = 32'h5be0cd19;

		a = 32'h6a09e667;
		b = 32'hbb67ae85;
		c = 32'h3c6ef372;
		d = 32'ha54ff53a;
		e = 32'h510e527f;
		f = 32'h9b05688c;
		g = 32'h1f83d9ab;
		h = 32'h5be0cd19;
		state = IDLE;
	end else
	begin
		case (state)
			IDLE: begin
				if(start) begin
					mem_we <= 'b0;
					mem_addr <= message_addr;
					state <= PRIME_ADDR;
				end
			end
			
			PRIME_ADDR: begin
				mem_addr <= message_addr + readOffset;
				w[15] <= mem_read_data;
				readOffset <= readOffset + 7'b1;
				state <= FIRST_READ;
			end
			
			FIRST_READ: begin
				w[15] <= mem_read_data;
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				state <= WAIT;
			end
			
			WAIT: begin
				w[15] <= mem_read_data;
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				state <= FIRST_16;
			end
			
			FIRST_16: begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				w[15] <= mem_read_data;
				for(i=0; i < 15; i++) w[i] <= w[i+1]; // doesnt match slides; moved before read line
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				tIndex <= tIndex+8'b1;
				
				if(tIndex == 15) begin
					w[15] <= wtnew();
					state <= NEXT_48; //next loop
				end
			end
			
			NEXT_48: begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				w[15] <= wtnew();
				for(i=0; i < 15; i++) w[i] <= w[i+1]; // doesnt match slides; moved before read line
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				tIndex <= tIndex+8'b1;
				
				if( tIndex == 63 ) begin
					state <= FINALIZE_HASH;
					readOffset <= 7'd16;
				end
			
			end
			
			FINALIZE_HASH: begin
			
				nonceIndex <= 7'b0; // Don't forget its 7 bits lol
				tIndex <= 'b0;
			
				fh0 <= fh0 + a;
				fh1 <= fh1 + b;
				fh2 <= fh2 + c;
				fh3 <= fh3 + d;
				fh4 <= fh4 + e;
				fh5 <= fh5 + f;
				fh6 <= fh6 + g;
				fh7 <= fh7 + h;
				state <= BEFORE_NONCE;
			end
			
			BEFORE_NONCE: begin
				mem_addr <= message_addr + readOffset;
				state <= NONCE;
			end
			
			NONCE: begin
				w[15] <= mem_read_data;
				mem_addr <= message_addr + readOffset;
				readOffset = readOffset + 7'b1;
				
				state <= BLOCK2_INIT;
			end
			
			BLOCK2_INIT: begin // Init 2nd block nonce calcs

				w[15] <= mem_read_data;
				mem_addr <= message_addr + readOffset;
				readOffset = readOffset + 7'b1;
				
				// Init hash
				h0[nonceIndex] = fh0;
				h1[nonceIndex] = fh1;
				h2[nonceIndex] = fh2;
				h3[nonceIndex] = fh3;
				h4[nonceIndex] = fh4;
				h5[nonceIndex] = fh5;
				h6[nonceIndex] = fh6;
				h7[nonceIndex] = fh7;

				a = fh0;
				b = fh1;
				c = fh2;
				d = fh3;
				e = fh4;
				f = fh5;
				g = fh6;
				h = fh7;
				
				state <= NONCE_BLOCK_2_WAIT;
			end
			
			NONCE_BLOCK_2_WAIT: begin
				w[15] <= mem_read_data;
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				state <= BLOCK2_WORD_EXP;
			end
			
			BLOCK2_WORD_EXP: begin // Block 2 word expansion; first 16
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				
				if(tIndex < 8'd2) w[15] <= mem_read_data;
				if(tIndex == 8'd2) w[15] <= nonceIndex;
				if(tIndex == 8'd3) w[15] <= 'h80000000;
				if(tIndex > 8'd3) w[15] <= 'd0;
				if(tIndex == 8'd14) w[15] <= 'h280;
				
				for(i=0; i < 15; i++) w[i] <= w[i+1];
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				tIndex <= tIndex+8'b1;

				if(tIndex == 15) begin
					w[15] <= wtnew();
					state <= HASH2_INIT; //next loop
				end
				
			end
			
			HASH2_INIT: begin // Init 2nd hash nonce calcs, next 48
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				w[15] <= wtnew();
				for(i=0; i < 15; i++) w[i] <= w[i+1]; // doesnt match slides; moved before read line
				mem_addr <= message_addr + readOffset;
				readOffset <= readOffset + 7'b1;
				tIndex <= tIndex+8'b1;
				
				if( tIndex == 63 ) state <= AFTER_NONCE;
			end
			
			START_BLOCK_3: begin
				if(tIndex == 8'd0) w[15] <= w[7];
				if(tIndex == 8'd1) w[15] <= w[8];
				if(tIndex == 8'd2) w[15] <= w[9];
				if(tIndex == 8'd3) w[15] <= w[10];
				if(tIndex == 8'd4) w[15] <= w[11];
				if(tIndex == 8'd5) w[15] <= w[12];
				if(tIndex == 8'd6) w[15] <= w[13];
				if(tIndex == 8'd7) w[15] <= w[14];
				state <= STALL_BLOCK_3;
			end
			
			STALL_BLOCK_3: begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				
				tIndex = tIndex + 7'b1;
				
				if(tIndex == 7'd8) begin
					w[15] <= 'h80000000;
					state <= EXP_BLOCK_3;
				 end else
					state <= START_BLOCK_3;
			end
			
			EXP_BLOCK_3: begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				if(tIndex < 7'd14 && tIndex > 7'd7) w[15] <= 'h0;
				if(tIndex == 7'd14) w[15] <= 'd256;
				
				for(i=0; i < 15; i++) w[i] <= w[i+1];
				tIndex <= tIndex+8'b1;
				
				if(tIndex == 15) begin
					w[15] <= wtnew();
					state <= HASH_BLOCK_3;
				end
			
			end
			
			HASH_BLOCK_3: begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], tIndex);
				w[15] <= wtnew();
				for(i=0; i < 15; i++) w[i] <= w[i+1]; // doesnt match slides; moved before read line
				tIndex <= tIndex+8'b1;
				
				if( tIndex == 63 ) state <= AFTER_NONCE;
			end
			
			AFTER_NONCE: begin
				// final hash vals
				h0[nonceIndex] <= h0[nonceIndex] + a;
				h1[nonceIndex] <= h1[nonceIndex] + b;
				h2[nonceIndex] <= h2[nonceIndex] + c;
				h3[nonceIndex] <= h3[nonceIndex] + d;
				h4[nonceIndex] <= h4[nonceIndex] + e;
				h5[nonceIndex] <= h5[nonceIndex] + f;
				h6[nonceIndex] <= h6[nonceIndex] + g;
				h7[nonceIndex] <= h7[nonceIndex] + h;

				nonceIndex <= nonceIndex+7'b1; 	// n++
				
				if(b2Done) begin
					state <= AFTER_BLOCK_3;
				end
				
				if(nonceIndex < 'd15 && !b2Done)begin
					tIndex <= 7'b0;
					readOffset <= 7'd16;
					state <= BEFORE_NONCE;
				end
				
				if ( nonceIndex == 'd15 && !b2Done ) begin // is nonce loop done
					b2Done <= 1'b1;

					w[7] <= h0[0];
					w[8] <= h1[0];
					w[9] <= h2[0];
					w[10] <= h3[0];
					w[11] <= h4[0];
					w[12] <= h5[0];
					w[13] <= h6[0];
					w[14] <= h7[0];
					w[15] <= h0[0];

					h0[0] <= 32'h6a09e667;
					h1[0] <= 32'hbb67ae85;
					h2[0] <= 32'h3c6ef372;
					h3[0] <= 32'ha54ff53a;
					h4[0] <= 32'h510e527f;
					h5[0] <= 32'h9b05688c;
					h6[0] <= 32'h1f83d9ab;
					h7[0] <= 32'h5be0cd19;

					a <= 32'h6a09e667;
					b <= 32'hbb67ae85;
					c <= 32'h3c6ef372;
					d <= 32'ha54ff53a;
					e <= 32'h510e527f;
					f <= 32'h9b05688c;
					g <= 32'h1f83d9ab;
					h <= 32'h5be0cd19;

					nonceIndex <= 7'b0;
					state <= START_BLOCK_3;
					tIndex <= 7'b0;
				end
			end
				
			AFTER_BLOCK_3: begin
				if(nonceIndex < 'd16 && b2Done) begin
					w[7] <= h0[nonceIndex];
					w[8] <= h1[nonceIndex];
					w[9] <= h2[nonceIndex];
					w[10] <= h3[nonceIndex];
					w[11] <= h4[nonceIndex];
					w[12] <= h5[nonceIndex];
					w[13] <= h6[nonceIndex];
					w[14] <= h7[nonceIndex];
					w[15] <= h0[nonceIndex];

					h0[nonceIndex] <= 32'h6a09e667;
					h1[nonceIndex] <= 32'hbb67ae85;
					h2[nonceIndex] <= 32'h3c6ef372;
					h3[nonceIndex] <= 32'ha54ff53a;
					h4[nonceIndex] <= 32'h510e527f;
					h5[nonceIndex] <= 32'h9b05688c;
					h6[nonceIndex] <= 32'h1f83d9ab;
					h7[nonceIndex] <= 32'h5be0cd19;

					a <= 32'h6a09e667;
					b <= 32'hbb67ae85;
					c <= 32'h3c6ef372;
					d <= 32'ha54ff53a;
					e <= 32'h510e527f;
					f <= 32'h9b05688c;
					g <= 32'h1f83d9ab;
					h <= 32'h5be0cd19;
					
					state <= START_BLOCK_3;
					tIndex <= 7'b0;
				end
				
				if(nonceIndex == 'd16) begin
					mem_addr <= output_addr + writeOffset;
					state <= WRITE_NONCES;
				end
				
			end
			
			WRITE_NONCES: begin
				begin
					mem_we = 1'b1;
					mem_write_data <= h0[0];
					for(i=0; i < 15; i++) h0[i] <= h0[i+1];
					mem_addr <= output_addr + writeOffset;
					
					if(writeOffset < 8'd16)
						writeOffset = writeOffset + 7'b1;
					else
						state <= DONE;
				end		
			end
						
			
			DONE: begin
				done = 1'b1;
			end

		endcase;
	end




end








endmodule 