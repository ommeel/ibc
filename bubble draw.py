import matplotlib.pyplot as plt
import numpy as np

# 创建一个计算第三维度的函数框架
m = 0.621
e = 0.427
p = 2.21
def calculate_third_dimension(k, n):

    """
    计算第三维度的函数框架。
    x: 第一个离散变量
    y: 第二个离散变量
    返回时间或其他第三维度的值
    """
    # 可以在此实现你自己的计算逻辑
    # 作为示例，这里我们返回 x 和 y 的和作为第三维度
    tm = 6*k+2*n-1
    te = 3*k+3*n-3
    tmp = (tm*m+te*e+te*p)/(2**n-1)
    
    return tmp

# 设置横纵坐标为 0-10 的离散整数
x_values = np.arange(1, 9)
y_values = np.arange(0, 9)

# 生成网格
x_grid, y_grid = np.meshgrid(x_values, y_values)

# 计算第三维度的值 (这里作为示例使用 calculate_third_dimension 函数)
third_dimension_values = calculate_third_dimension(x_grid, y_grid)

# 展开网格用于绘制气泡图
x_flat = x_grid.flatten()
y_flat = y_grid.flatten()
third_dimension_flat = third_dimension_values.flatten()

# 绘制气泡图
plt.figure(figsize=(8, 6))
plt.scatter(x_flat, y_flat, s=third_dimension_flat * 10, alpha=0.6, edgecolors="w", linewidth=1)

# 设置图表标题和轴标签
plt.title("Private Key Generation Time", fontsize=14)
plt.xlabel("k", fontsize=12)
plt.ylabel("n", fontsize=12)
# plt.grid(True)

# 显示图表
# # plt.show()
# 保存图像为可编辑的 SVG 或 PDF 矢量图格式
plt.savefig("my_figure.svg", format='svg', bbox_inches='tight')  # 保存为 SVG 格式
plt.show()
print('done')
