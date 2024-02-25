use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use std::{time::Duration, time::Instant, io, io::Write, fs::File, fs};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT};
use sha256::digest;
use hex::FromHex;

// Definition of structure for the proof.
#[derive(Debug)]
pub enum Proof{

    Proofplay{r_0: RistrettoPoint, r_1: RistrettoPoint, z_z: Scalar},
    Error{err: bool},
}

// It generates a random scalar (given in the curve25519_dalek library).
fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// It generates a random RistrettoPoint.
pub fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}

// It converts a [u8; 32] in Scalar.
fn convert_scalar(a: [u8; 32]) -> Scalar{
    
	let s = Scalar::from_bytes_mod_order(a);
	return s
}	       

// It converts a RistrettoPoint in [u8; 32].
fn convert_ris(t: RistrettoPoint) -> [u8; 32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption/Decryption:
fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint, Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint, pk: RistrettoPoint, m: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint){ 

    let r = random_scalar(csprng);
    let c1 = r * g;
    let c2 = m + r * pk;
    return (c1, c2)
}
	
fn dec_elgamal(sk: Scalar, c1: RistrettoPoint, c2: RistrettoPoint) -> RistrettoPoint{ 
	
    let m = c2 - sk * c1 ;
    return m
}
	
// It hashes and concatenates a RistrettoPoint vector.
fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
    let mut k: Vec<[u8; 32]> = Vec::new();		
    for p in input {
	let p_p = convert_ris(p);
	k.push(p_p);
    }
    let conc = k.concat();
    let h = digest(&conc); 
    let v = <[u8; 32]>::from_hex(h);
    let mut u = [0u8; 32];   
    for j in 0..32{  
        u[j] = v.unwrap()[j];
    }
    return convert_scalar(u);      
}

// It generates a random vector of clue, the vector a corresponds to the encoding of false/true in RistrettoPoint.
pub fn buildclue(a: Vec<RistrettoPoint>, n: usize) -> Vec<RistrettoPoint>{

    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut rng = rand::thread_rng();  
    for _x in 0..n{
        let b: bool = rng.gen_bool(0.5);
        if b == true {
            clue.push(a[1]);
        }
        else {
            clue.push(a[0]);
        }
    }
    return clue;
}

// It measures the running time of the algorithm GenClue, OpenClue, Play and Verify and the size of the files containing pc and proof.
pub fn measurementscc1<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, a: Vec<RistrettoPoint>, n: usize, iter: u32){
    
    println!("Average of the computation time of the algorithms GenClue, OpenClue, Play and Verify, and measurements of the size of the public clue key and the proof over {:?} iterations.\n", iter);   
    println!("Execution in progress...\n(It can take a long time)\n");

    let playeranswer = vec![0,1];
  
    let mut sumgenclue = Duration::ZERO;
    let mut sumopenclue = Duration::ZERO;   
    let mut sumplay = [Duration::ZERO; 2];
    let mut sumverify = [Duration::ZERO; 2]; 
    
    let mut pcsize = 0;
    let mut proofsize = vec![0, 0];
    let mut averageproofsize = vec![0, 0];

    for _j in 0..iter{
    
        let clue = buildclue((&a).to_vec(), n);        
        let startgen = Instant::now(); 
        let keyc = genclue(csprng, g0, (&clue).to_vec()); 
        let gentime = startgen.elapsed();
        sumgenclue += gentime;
     
        let pc = keyc.0; // pc = (pk, c11, c21, c12, c22, ..., c1n, c2n) where n is the size of map.
        let sc = keyc.1; // sc = sk.
        let _ = writepc((&pc).to_vec()); // It allows to write the public clue key in the file "pc.txt".
    	let pcdata = fs::metadata("pc.txt"); 
    	pcsize += pcdata.expect("REASON").len(); // It allows to measures the size of the file "pc.txt". 
    	
        let startopenclue = Instant::now();
        let open = openclue((&pc).to_vec(), sc);
        let opencluetime = startopenclue.elapsed();  
        assert!(open == clue, "The open clue is not equal to the clue.");
        sumopenclue += opencluetime;  
    	
    	for k in 0..2{ // k corresponds to the type of clue : true or false, which depend of the answer, for our measurements the algorithm find a cell j such that clue[j] = a[k] where a[0] is the encoding of false and a[1] is the encoding of true.
            
            let answer = playeranswer[k];
            let mut j = 0;
            while clue[j] != a[k]{
	        j += 1;
            }
    
    	    let startplay = Instant::now();
            let proof = play(csprng, g0, (&a).to_vec(), (&pc).to_vec(), sc, j, answer);
            let playtime = startplay.elapsed();
            sumplay[k] += playtime;
            let _ = writeproof(&proof);
    	    let proofdata = fs::metadata("proof.txt");
    	    proofsize[k] += proofdata.expect("REASON").len();
        
            let startverify = Instant::now();
            let b = verify(g0, (&a).to_vec(), proof, (&pc).to_vec(), j, answer);
            let verifytime = startverify.elapsed();
            assert!(b == true , "Verify is false.");
            println!("Answer is {:?} and Verify is {:?}.", answer, b);
            sumverify[k] += verifytime;     
        }
    }
    let averagegen = sumgenclue/iter;
    let averageopen = sumopenclue/iter;
    let averagepcsize = pcsize/u64::from(iter);
     
    println!("\nGenClue: {:?},\nOpenclue: {:?},\nSize of public clue key: {:?} bytes.\n", averagegen, averageopen, averagepcsize);
    
    for k in 0..2{ // It calculates an average of running time of algorithms GenClue, OpenClue, Play and Verify and the size of public.
    
        let averageplay = sumplay[k]/iter;
        let averageverify = sumverify[k]/iter;
        
    	averageproofsize[k] = proofsize[k]/u64::from(iter);
    
        println!("Answer: {:?}\nPlay: {:?}\nVerify: {:?}\nSize of proof: {:?} bytes.\n", k, averageplay, averageverify, averageproofsize[k]);   
    }
}

// It write the public clue and the proof in a file.
fn writepc(pc: Vec<RistrettoPoint>) -> io::Result<()>{
    let mut file = File::create("pc.txt")?;
    file.write_fmt(format_args!("{:?}",pc))?;
    return Ok(())
}

fn writeproof(proof: &Proof) -> io::Result<()>{
    let mut file = File::create("proof.txt")?;
    file.write_fmt(format_args!("{:?}", proof))?;
    return Ok(())
}
 	   
// Algorithms for CC1:
// GenClue:
pub fn genclue<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>, Scalar){

    let key = gen_elgamal(csprng, g0); // key.0 = g, key.1 = pk and key.2 = sk.
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue {
        let e = enc_elgamal(csprng, g0, pc[0], c);
	pc.push(e.0); // It corresponds to c1. 
	pc.push(e.1); // It corresponds to c2.	
    }
    return (pc, key.2)
}  

// OpenClue:
pub fn openclue(pc: Vec<RistrettoPoint>, sc: Scalar) -> Vec<RistrettoPoint>{
    
    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut k = 1;
    while k < pc.len(){
        let c = dec_elgamal(sc, pc[k], pc[k+1]);
        clue.push(c); 
        k +=2;  
    } 
    return clue
}

// Answer: a is the encoding vector of false/true in RistrettoPoint.
pub fn algoanswer(a: Vec<RistrettoPoint>, clue: Vec<RistrettoPoint>, j: usize) -> usize{
    
    if clue[j] == a[0]{
    	return 0;
    }
    else{
    	return 1;
    } 
}

// Play: 
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, a: Vec<RistrettoPoint>, pc: Vec<RistrettoPoint>, sc: Scalar, j: usize, answer: usize) -> Proof{
    
    let y0 = pc[0];
    let c1 = pc[2*j+1];
    let c2 = pc[2*j+2];
    
    if answer == 0 || answer == 1{
    	let y = c2 - a[answer];
    	let p = prove_play(csprng, y0, y, g0, c1, sc);
    	return p; 
    }
    else{
    	println!("Please give a correct answer");
    	return  Proof::Error{err: false};
    }
}

fn prove_play<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: RistrettoPoint, g0: RistrettoPoint, g: RistrettoPoint, x: Scalar) -> Proof{
	
    // Commit:
    let rr = random_scalar(csprng);
    let r0 = rr * g0;
    let r = rr * g;
    
    // Challenge: 
    let conc = vec![r0, r, y0, y, g0, g];
    let cc = hash_vec(conc);
    
    // Response: 
    let zz = rr + cc * x;

    return Proof::Proofplay{r_0: r0, r_1: r, z_z: zz}; 
}

// Verify:
pub fn verify(g0: RistrettoPoint, a: Vec<RistrettoPoint>, proof: Proof, pc: Vec<RistrettoPoint>, j: usize, answer: usize) -> bool{

    let y0 = pc[0];
    let g = pc[2*j+1];
    let y = pc[2*j+2] - a[answer];
    
    match proof{
    	Proof::Proofplay{r_0, r_1, z_z} =>{ 
    	    return verify_play(y0, y, g0, g, r_0, r_1, z_z); 
    	},
    	Proof::Error{err} =>{  
    	    return err;   
    	},	
    }
}

fn verify_play(y0: RistrettoPoint, y: RistrettoPoint, g0: RistrettoPoint, g: RistrettoPoint, r0: RistrettoPoint, r: RistrettoPoint, zz: Scalar) -> bool{
    
    let conc = vec![r0, r, y0, y, g0, g];
    let cc = hash_vec(conc);
    
    if (zz * g0 == r0 + cc * y0) && (zz * g == r + cc * y){
    	return true;
    }
    else{
    	return false;
    }
}
