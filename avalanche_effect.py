
def xor(file1, file2, outfile):
   with open(file1,'r') as f1:
       lines1 = f1.readlines()
   with open(file2,'r') as f2:
       lines2 = f2.readlines()

   text1 = int(lines1[0], 16)
   text2 = int(lines2[0], 16)
   xored = text1 ^ text2 # XOR the two decimal numbers
   binary = bin(xored).replace("0b", "") # convert the decimal to binary
   with open(file3,'w') as f3:
      f3.write(binary)

   all_count = 0
   for i in bin(text1):
      all_count += 1
   return binary, all_count
   
class Solution(object):
   def hammingWeight(self, n):
      one_count = 0
      for i in n:
         if i == '1':
            one_count+=1
      return one_count

file1 = 'text1.txt'
file2 = 'text2.txt'
file3 = 'xored.txt'
binary, all_count = xor(file1, file2, file3)
ob1 = Solution()
one_count = ob1.hammingWeight(binary)
print('ANTAL 1:', one_count)
print('TOTAL BITAR:', all_count)
print('AVALANCHE EFFECT IN PERCENT:', one_count/all_count*100)
