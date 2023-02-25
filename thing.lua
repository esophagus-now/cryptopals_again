package.cpath = "./?.so"
cp = require"cp"

-- math.randomseed(12345678)

assert(hamming("this is a test", "wokka wokka!!!") == 37)
test = "123a123b123c12"
assert(downsample(test,4,1) == "1111")
assert(downsample(test,4,2) == "2222")
assert(downsample(test,4,3) == "333")
assert(downsample(test,4,4) == "abc")
assert(b642bin(bin2b64(test)) == test)
assert(b642bin(bin2b64(test.."%")) == test.."%")
assert(b642bin(bin2b64(test.."%?")) == test.."%?")

f = assert(io.open"timemachine.txt")
corpus = f:read"*a"
exp_freq = charfreq(corpus)
f = nil
corpus = nil

function freq_err(ref, candidate)
    assert(#ref == #candidate)

    local ret = 0
    for i,v in ipairs(ref) do
        local err = candidate[i] - v
        ret = ret + err*err
        -- ret = ret + (v+1)/(candidate[i]+1) - 1
    end

    return ret
end

-- Returns winner, key byte, and score
function break_single_char_xor(ciphertext)
    local best = ciphertext
    local key = 0
    local best_score = freq_err(exp_freq, charfreq(ciphertext))

    for i = 1,255 do
        local bin = string.char(i)
        local candidate = binxor(ciphertext, bin)
        --print(i, bin2hex(bin), bin2hex(candidate))
        local score = freq_err(exp_freq, charfreq(candidate))
        if (score < best_score) then
            best = candidate
            key = i
            best_score = score
        end
    end

    return best, string.char(key), best_score
end

-- Lower is better
function key_sz_score(ciphertext, key_sz)
    local len = #ciphertext
    assert(len >= 2*key_sz)

    local num_samples = 3 -- arbitrary
    -- local num_samples = len - (2*key_sz-1)
    -- local num_samples = 1
    
    local dist_sum = 0
    for i = 1,num_samples do
        -- Pick a random starting location in ciphertext where we will
        -- pull two adjacent chunks of key_sz bytes. This means the
        -- base index + (2*key_sz - 1) cannot overflow the string. 
        -- Recall: math.random returns any number from 1 to n (inclusive)
        local base = math.random(len - (2*key_sz-1))
        -- local base = i

        local chunk1 = ciphertext:sub(base, base + key_sz - 1)
        local chunk2 = ciphertext:sub(base + key_sz, base + 2*key_sz - 1)

        dist_sum = dist_sum + hamming(chunk1, chunk2)
    end

    return dist_sum / (num_samples*key_sz)
end

-- Challenge 1
function set1_challenge1()
    print"Set 1 Challenge 1"
    local input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    local golden = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    
    local bin = hex2bin(input)
    print(bin)
    local b64 = bin2b64(bin)
    print(b64)
    assert(b64 == golden)
end

-- Challenge 2
function set1_challenge2()
    print"Set 1 Challenge 2"
    local input1 = hex2bin"1c0111001f010100061a024b53535009181c"
    local input2 = hex2bin"686974207468652062756c6c277320657965"
    local golden = hex2bin"746865206b696420646f6e277420706c6179"

    local xored = binxor(input1, input2)
    print(xored)
    assert(xored == golden)
end

function set1_challenge3()
    print"Set 1 Challenge 3"
    local ciphertext = hex2bin("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    local winner = break_single_char_xor(ciphertext)
    
    print(winner)
    --print(best_score)
end

function set1_challenge4()
    print"Set 1 Challenge 4"
    local f = assert(io.open"4.txt")
    local best = "ERROR"
    local best_score = 300 -- Error is bounded by 256
    for l in f:lines() do
        local ciphertext = hex2bin(l)
        local winner, k, score = break_single_char_xor(ciphertext)
        if score < best_score then
            best = winner
            best_score = score
        end
    end

    print(best)
end

function set1_challenge5()
    print"Set 1 Challenge 5"
    local input = [[
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal]]
    local golden = hex2bin(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"..
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )

    local key = "ICE"

    local ciphertext = binxor(input, key)
    assert(ciphertext == golden)
    print"Success"
end

function set1_challenge6()
    -- Interesting. Let a and b be arbitrary bytes with Hamming distance h.
    -- Then, the Hamming distance from a^k to b^k (i.e. the distance between
    -- both bytes if they were XORed against the same key) is still h. This
    -- is because if a bit was the same in a and b, it is still the same after
    -- XORing with the same key bit (and likewise if they were originally
    -- different).

    local f = assert(io.open"6.txt")
    local ciphertext = {}
    for l in f:lines() do
        table.insert(ciphertext, l)
    end
    ciphertext = b642bin(table.concat(ciphertext))
    f = nil
    print("Ciphertext length = ", #ciphertext)

    local scores = {}

    for i = 1,40 do
        local key_sz_score = key_sz_score(ciphertext, i)
        table.insert(scores, {sz = i, score = key_sz_score})
    end

    -- Technically we could use nth_element to get top n, but it's
    -- not in the C or Lua standard libraries so whatever.
    table.sort(scores, function(a,b) return a.score < b.score end)

    local best_score = 300
    local best_key = "ERROR"
    local best = "ERROR"
    
    for i = 1,3 do
        local sz = scores[i].sz
        print("Key size", sz, "has score", scores[i].score)
        local key = ""
        local score_sum = 0
        for j = 1,sz do
            local strip = downsample(ciphertext, sz, j)
            local _, k, score = break_single_char_xor(strip)
            score_sum = score_sum + score
            key = key .. k
        end
        local score = score_sum / sz -- Average score of all strips
        if (score < best_score) then
            best_score = score
            best_key = key
            best = binxor(ciphertext, key)
        end
    end
    
    io.write("Inferred key = [", best_key, "] with length ", #best_key, "\n")
    print(best)
    
end

-- set1_challenge1()
-- set1_challenge2()
-- set1_challenge3()
-- set1_challenge4()
-- set1_challenge5()
set1_challenge6()