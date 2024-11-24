from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import time
import hashlib


group = PairingGroup('MNT224')


g1 = group.random(G1)  
g2 = group.random(G2) 
a = group.random(ZR)  
mod_value = group.order()
 
iterations = 1

# 计算点乘法的时间
point_multiplication_time = 0
for _ in range(iterations):
    start_time = time.time()
    point_multiplication = g1 ** a
    end_time = time.time()
    point_multiplication_time += (end_time - start_time)
average_point_multiplication_time = point_multiplication_time / iterations
print(f"Average point multiplication time over {iterations} iterations: {average_point_multiplication_time} seconds")

# 计算点加法的时间
point_addition_time = 0
for _ in range(iterations):
    start_time = time.time()
    point_addition = g1 + g1
    end_time = time.time()
    point_addition_time += (end_time - start_time)
average_point_addition_time = point_addition_time / iterations
print(f"Average point addition time over {iterations} iterations: {average_point_addition_time} seconds")

# 计算双线性对的时间
bilinear_pairing_time = 0
for _ in range(iterations):
    start_time = time.time()
    bilinear_pairing = pair(g1, g2)
    end_time = time.time()
    bilinear_pairing_time += (end_time - start_time)
average_bilinear_pairing_time = bilinear_pairing_time / iterations
print(f"Average bilinear pairing time over {iterations} iterations: {average_bilinear_pairing_time} seconds")

# 计算模幂运算的时间 (g1 ** a) % mod_value
mod_exp_time = 0
for _ in range(iterations):
    start_time = time.time()
    mod_exp_result = pow(g1, a, mod_value)  
    end_time = time.time()
    mod_exp_time += (end_time - start_time)
average_mod_exp_time = mod_exp_time / iterations
print(f"Average modular exponentiation time over {iterations} iterations: {average_mod_exp_time} seconds")


# 计算MD5哈希的时间
md5_hash_time = 0
for _ in range(iterations):
    start_time = time.time()
    md5_hash = hashlib.md5(str(g1).encode()).hexdigest()
    end_time = time.time()
    md5_hash_time += (end_time - start_time)
average_md5_hash_time = md5_hash_time / iterations
print(f"Average MD5 hash time over {iterations} iterations: {average_md5_hash_time} seconds")

# 计算SHA256哈希的时间
sha256_hash_time = 0
for _ in range(iterations):
    start_time = time.time()
    sha256_hash = hashlib.sha256(str(g1).encode()).hexdigest()
    end_time = time.time()
    sha256_hash_time += (end_time - start_time)
average_sha256_hash_time = sha256_hash_time / iterations
print(f"Average SHA256 hash time over {iterations} iterations: {average_sha256_hash_time} seconds")