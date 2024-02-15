use rand_core::{CryptoRng,RngCore};
use curve25519_dalek::{ristretto::RistrettoPoint,scalar::Scalar,traits::Identity,constants::RISTRETTO_BASEPOINT_POINT};
use sha256::digest;
use hex::FromHex;
use rand::Rng;
use std::{time::Duration,time::Instant,io,io::Write,fs::File,fs};

// We use the bibrairy curve25519_dalek: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/

// Definition of structure Proof
#[derive(Debug)]
pub enum Proof{

    Proofplay{r_0: RistrettoPoint, r_1: RistrettoPoint, z_z: Scalar},
    Error{err: bool},
}

// Generates a random scalar // from curve25519_dalek librairy
pub fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// Generates a random RistrettoPoint
pub fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}
    
// Converts a Scalar in [u8;32]
pub fn convert_u832(a: Scalar) -> [u8;32]{
    
    let u = (&a).to_bytes();
    return u
}

// Converts a [u8;32] in Scalar
pub fn convert_scalar(a: [u8;32]) -> Scalar{
    
	let s = Scalar::from_bytes_mod_order(a);
	return s
}	       

// Converts a RistrettoPoint in [u8;32]
pub fn convert_ris(t: RistrettoPoint) -> [u8;32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption/Decryption
pub fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T,g: RistrettoPoint) -> (RistrettoPoint,RistrettoPoint,Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
pub fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T,g: RistrettoPoint,pk: RistrettoPoint,m: RistrettoPoint) -> (RistrettoPoint,RistrettoPoint){ 
	
	let r = random_scalar(csprng);
	let c1 = r * g;
	let c2 = m + r * pk;
	return (c1,c2)
}
	
pub fn dec_elgamal(sk: Scalar,c1: RistrettoPoint,c2: RistrettoPoint) -> RistrettoPoint{ 
	
	let m = c2 - sk * c1 ;
	return m
}
	
// Hash on Vec<RistrettoPoint> 
pub fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
    let mut k: Vec<[u8;32]> = Vec::new();
		
    for p in input {
	let p_p = convert_ris(p);
	k.push(p_p);
    }
    let conc = k.concat();
    let h = digest(&conc); 
    let v = <[u8;32]>::from_hex(h);
    let mut u = [0u8;32];
        
    for j in 0..32{  
        u[j] = v.unwrap()[j];
    }
    return convert_scalar(u);      
}
 
// Initializes vector  of len t
pub fn init_vec_ris(t: usize) -> Vec<RistrettoPoint>{

    let vec = vec![RistrettoPoint::identity();t];
    return vec
}

pub fn init_vec_scal(t: usize) -> Vec<Scalar> {
    
    let vec = vec![convert_scalar([0u8;32]);t];
    return vec
}

// Generates a random vector of clue, the vector a corresponds to the encoding of false/true in RistrettoPoint
pub fn buildrandomclue(a: Vec<RistrettoPoint>) -> Vec<RistrettoPoint>{

    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut rng = rand::thread_rng();  
    for _x in 0..108{
        let b : bool = rng.gen_bool(0.5);
        if b == true {
            clue.push(a[1]);
        }
        else {
            clue.push(a[0]);
        }
    }
    return clue;
}

// Measures the running time of the algorithm genclue, openclue, play and verify and the size of the files containing pc and proof
pub fn mesuretimeandsize<T: CryptoRng + RngCore>(csprng:&mut T,g0: RistrettoPoint,a: Vec<RistrettoPoint>,iter: u32){

    let answerplayer = vec![0,1];
    
    let mut sumgenclue = Duration::ZERO;
    let mut sumopenclue = Duration::ZERO;   
    let mut sumplay = [Duration::ZERO;2];
    let mut sumverify = [Duration::ZERO;2]; 
    
    let mut pcsize = 0;
    let mut proofsize = vec![0,0];
    
    let mut meanproofsize = vec![0,0];

    for _j in 0..iter{
    
        let clue = buildrandomclue((&a).to_vec());
        
        let startgen = Instant::now();
        let keyc = genclue(csprng,g0,(&clue).to_vec()); 
        let gentime = startgen.elapsed();
        sumgenclue += gentime;
     
        let pc = keyc.0; 
        let sc = keyc.1;
        let _ = writepc((&pc).to_vec());
    	let pcdata = fs::metadata("pc.txt");
    	pcsize += pcdata.expect("REASON").len();
    	
        let startopenclue = Instant::now();
        openclue((&pc).to_vec(),sc);
        let opencluetime = startopenclue.elapsed();  
        //assert!(open == clue,"open != clue");
        sumopenclue += opencluetime;  
    	
    	for k in 0..2{  
            let answer = answerplayer[k];
    
            let mut j = 0;
            while clue[j] != a[k]{
	        j += 1;
            }
            
            /*let mut badanswer = 2;
            if answer == 0{
    	        badanswer = 1;
            }
            else{
    	        badanswer = 0;
            }*/
    
    	    let startplay = Instant::now();
            let proof = play(csprng,g0,(&a).to_vec(),(&pc).to_vec(),sc,j,answer);
            let playtime = startplay.elapsed();
            sumplay[k] += playtime;
            let _ = writeproof(&proof);
    	    let proofdata = fs::metadata("proof.txt");
    	    proofsize[k] += proofdata.expect("REASON").len();
        
            let startverify = Instant::now();
            verify(g0,(&a).to_vec(),proof,(&pc).to_vec(),j,answer);
            let verifytime = startverify.elapsed();
            //assert!(b == true , "verify = false");
            //println!("verify: {:?}",b ==true);
            sumverify[k] += verifytime;     
        }
    } 
    for k in 0..2{
    
        let meangen = sumgenclue/iter;
        let meanopen = sumopenclue/iter;
        
        let meanplay = sumplay[k]/iter;
        let meanverify = sumverify[k]/iter;
        
        let meanpcsize = pcsize/u64::from(iter);
    	meanproofsize[k] = proofsize[k]/u64::from(iter);
    
        println!("for answer {:?}: mean over {:?} iterations, for genclue {:?}, for openclue {:?}, for play {:?}, for verify {:?}",k,iter,meangen,meanopen,meanplay,meanverify);
        println!("for answer {:?}: mean of size file over {:?} iterations, for pc {:?} bytes, for proof {:?} bytes",k,iter,meanpcsize,meanproofsize[k]);    
    }
}

// For measuring size of files
pub fn writepc(pc: Vec<RistrettoPoint>) -> io::Result<()>{
    let mut file = File::create("pc.txt")?;
    file.write_fmt(format_args!("{:?}",pc))?;
    return Ok(())
}

pub fn writeproof(proof: &Proof) -> io::Result<()>{
    let mut file = File::create("proof.txt")?;
    file.write_fmt(format_args!("{:?}",proof))?;
    return Ok(())
}

// Scheme cc1
pub fn schemecc1<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,a: Vec<RistrettoPoint>,clue: Vec<RistrettoPoint>,j: usize,answer: usize){

    let startgenclue = Instant::now();
    let keyc = genclue(csprng,g0,(&clue).to_vec()); 
    let gencluetime = startgenclue.elapsed();
    println!("genclue took {:?}",gencluetime);
                       
    let pc = keyc.0; //pc = (pk, E1=(c1i,c2i)_{i in [N]}) , Ei=Enc_pk(clue[i])
    let sc = keyc.1; //sc = sk
    let _ = writepc((&pc).to_vec());

    let startopenclue = Instant::now();
    let open = openclue((&pc).to_vec(),sc);
    let opencluetime = startopenclue.elapsed();
    println!("openclue took {:?}",opencluetime);    
    assert!(open == clue,"open != clue");
     
    let startplay = Instant::now();
    let proof = play(csprng,g0,(&a).to_vec(),(&pc).to_vec(),sc,j,answer);
    let _ = writeproof(&proof);
    let playtime = startplay.elapsed();
    println!("play took {:?}",playtime);
	    
    let startverify = Instant::now();
    let b = verify(g0,(&a).to_vec(),proof,(&pc).to_vec(),j,answer);
    let verifytime = startverify.elapsed(); 
    println!("verify took {:?}\n",verifytime);

    println!("answer: {:?} ; verify: {:?}\n",answer,b);
}
 	   
// Function for cc1
// Genclue
pub fn genclue<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>,Scalar){

    let key = gen_elgamal(csprng,g0); // key.0 = g, key.1 = pk, key.2 = sk
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue {
        let e = enc_elgamal(csprng,g0,pc[0],c);
	pc.push(e.0); //c1 
	pc.push(e.1); //c2	
    }
    return (pc, key.2)
}  

// Openclue
pub fn openclue(pc: Vec<RistrettoPoint>,sc: Scalar) -> Vec<RistrettoPoint>{
    
    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut k = 1;
    while k < pc.len(){
        let c = dec_elgamal(sc, pc[k], pc[k+1]);
        clue.push(c); 
        k +=2;  
    } 
    return clue
}

// Answer : a is the encoding vector of true and false in RistrettoPoint
pub fn funanswer(a: Vec<RistrettoPoint>,clue: Vec<RistrettoPoint>,j: usize) -> usize{
    
    if clue[j] == a[0]{
    	return 0;
    }
    else{
    	return 1;
    } 
}

// Play 
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,a: Vec<RistrettoPoint>,pc: Vec<RistrettoPoint>,sc: Scalar,j: usize,answer: usize) -> Proof{
    
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

pub fn prove_play<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: RistrettoPoint,g0: RistrettoPoint,g: RistrettoPoint,x: Scalar) -> Proof{
	
    // commit
    let rr = random_scalar(csprng);
    let r0 = rr * g0;
    let r = rr * g;
    
    // challenge 
    let conc = vec![r0,r,y0,y,g0,g];
    let cc = hash_vec(conc);
    
    // response 
    let zz = rr + cc * x;

    return Proof::Proofplay{r_0: r0, r_1: r, z_z: zz}; 
}

// Verify
pub fn verify(g0: RistrettoPoint,a: Vec<RistrettoPoint>,proof: Proof,pc: Vec<RistrettoPoint>,j: usize,answer: usize) -> bool{

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

pub fn verify_play(y0: RistrettoPoint,y: RistrettoPoint,g0: RistrettoPoint,g: RistrettoPoint,r0: RistrettoPoint,r: RistrettoPoint,zz: Scalar) -> bool{
    
    let conc = vec![r0,r,y0,y,g0,g];
    let cc = hash_vec(conc);
    
    if (zz * g0 == r0 + cc * y0) && (zz * g == r + cc * y){
    	return true;
    }
    else{
    	return false;
    }
}

