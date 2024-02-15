use rand_core::{CryptoRng, RngCore};
use rand::Rng;
use curve25519_dalek::{ristretto::RistrettoPoint,scalar::Scalar,traits::Identity,constants::RISTRETTO_BASEPOINT_POINT};
use sha256::digest;
use hex::FromHex;
use std::{time::Duration,time::Instant,io,io::Write,fs::File,fs};

//https://ristretto.group/why_ristretto.html
//https://datatracker.ietf.org/meeting/109/materials/slides-109-cfrg-ristrettodecaf-00
//we use the librairy curve25519_dalek: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/

// Definition of structure for proofs
#[derive(Debug)]
pub enum Proof{

    ProofMaybe{r_0: RistrettoPoint, r_1: Vec<RistrettoPoint>, c_1: Vec<Scalar>, z_0: Scalar, z_1: Vec<Scalar>},
    ProofNo{y_0_p: RistrettoPoint, y_1_p: Vec<RistrettoPoint>, r_0: RistrettoPoint, r_r: Vec<RistrettoPoint>, s_0: RistrettoPoint, s_s: Vec<RistrettoPoint>, u_u: Scalar, v_v: Scalar},
    Error{err: bool},
}

// Generates a random scalar from curve25519_dalek librairy
fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// Generates a random RistrettoPoint
fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}

// Converts a [u8;32] in Scalar
fn convert_scalar(a: [u8;32]) -> Scalar{
    
    let s = Scalar::from_bytes_mod_order(a);
    return s
}	       

// Converts a RistrettoPoint in [u8;32]
fn convert_ris (t: RistrettoPoint) -> [u8;32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption / Decryption
fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T,g: RistrettoPoint) -> (RistrettoPoint,RistrettoPoint,Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
pub fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T,g: RistrettoPoint,pk: RistrettoPoint,m: RistrettoPoint)-> (RistrettoPoint,RistrettoPoint){ 
	
    let r = random_scalar(csprng);
    let c1 = r * g;
    let c2 = m + r * pk;
    return (c1,c2)
}
	
fn dec_elgamal(sk: Scalar,c1: RistrettoPoint,c2: RistrettoPoint)-> RistrettoPoint{ 

    let m = c2 - sk * c1 ;
    return m
}
	
// Hash on Vec<RistrettoPoint> 
fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
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
 
// Initializes vector  
fn init_vec_ris(t: usize) -> Vec<RistrettoPoint>{

    let vec = vec![RistrettoPoint::identity();t];
    return vec
}

fn init_vec_scal(t: usize) -> Vec<Scalar> {
    
    let vec = vec![convert_scalar([0u8;32]);t];
    return vec
}
    	   
// Setup of map, clues...

// Generation of types and properties
pub fn typesandproperties<T: CryptoRng + RngCore>(csprng: &mut T) -> (Vec<RistrettoPoint>,Vec<RistrettoPoint>){
    
    let mut t: Vec<RistrettoPoint> = Vec::new();
    let mut p: Vec<RistrettoPoint> = Vec::new();
	
    // gen types
    let mut k = 0;
    while k < 5{
        let ti = random_point(csprng);
        t.push(ti);
        k = k + 1;
    }
    
    // gen properties
    k = 0;
    while k < 14{
        let pi = random_point(csprng);
        p.push(pi);
        k = k + 1;
    }
    return(t,p)
}

// Generates a specific cell with type t and properties p
pub fn gencell(t: Vec<RistrettoPoint>,p: Vec<RistrettoPoint>,w: usize,mut x: Vec<usize>) -> (RistrettoPoint,Vec<RistrettoPoint>){
    
    let ti = t[w];
    let mut pi: Vec<RistrettoPoint> = Vec::new();
    x.sort();

    let mut k = 0;
    for i in 0..14{
    	if k < x.len(){
    	    if i == x[k]{
        	let px = p[i];
        	pi.push(px);
        	k = k + 1;
            }
        }
    }
    return(ti,pi)
}

// Generates a random cell
pub fn randomcell (t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>) -> (RistrettoPoint, Vec<RistrettoPoint>){
     
    let mut rng = rand::thread_rng(); 
    
    let w: usize = rng.gen_range(0..5);
    
    let n: usize = rng.gen_range(1..13); // n = number of properties
    let mut x: Vec<usize> = Vec::new(); 
    
    let mut k = 0;
    while k < n{
       
        let z : usize = rng.gen_range(0..14);
        if x.contains(&z){
            continue;
        }
        else{
            x.push(z);
        }
        k = k + 1;    
    }
    let ci = gencell(t,p,w,x);
    return ci
}

// Build a  random clue: i = 0 correspond to (tj,tk,bot) with tj =/= tk, i = 1 corespond to (bot,bot,p) with p in pj, i = 2 correspond to (ti,tk,bot) with tj =/= tk =/= ti =/= tj, i = 3 correspond to (bot,bot,p) with p not in pj
pub fn buildrandomclue(t: Vec<RistrettoPoint>,p: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,k: usize) -> Vec<RistrettoPoint>{

    let mut rng = rand::thread_rng(); 
    let bottom = RISTRETTO_BASEPOINT_POINT; 
    
    if k == 0{

        let mut r1 = rng.gen_range(0..5);
        while t[r1] == tj{
    	    r1 = rng.gen_range(0..5);    
        }
        let r = rng.gen_bool(0.5);
        if r == true{
            return vec![tj,t[r1],bottom];
        }
        else{
            return vec![t[r1],tj,bottom];
        }
    }
    if k == 1{
    
        let r2 = rng.gen_range(0..pj.len());
        return vec![bottom,bottom,pj[r2]];
    }    
    if k == 2{
    	
    	let mut r3 = rng.gen_range(0..5);
    	let mut r4 = rng.gen_range(0..5);
    	while t[r3] == tj || t[r4] == tj || t[r3] == t[r4]{
            r3 = rng.gen_range(0..5);
    	    r4 = rng.gen_range(0..5);
    	}
    	return vec![t[r3],t[r4],bottom];
    }
    if k == 3{

    	let mut r5 = rng.gen_range(0..14);
    	while pj.contains(&p[r5]){
    	    r5 = rng.gen_range(0..14);
   	}
   	return vec![bottom,bottom,p[r5]];
    }
    else{
    	println!("Please give a correct form of clue");
    	return vec![bottom,bottom,bottom];
    }	
}

// Measures the running time of algorithm genclue, openclue, play, verify and the size of pc and proof for the protocol cc2
pub fn mesuretimeandsize<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, iter: u32){
    
    let mut sumgenclue = vec![Duration::ZERO;4];
    let mut sumopenclue = vec![Duration::ZERO;4];
    let mut sumplay = vec![Duration::ZERO;4];
    let mut sumverify = vec![Duration::ZERO;4];
    
    let mut meangen = vec![Duration::ZERO;4];
    let mut meanopen = vec![Duration::ZERO;4];
    let mut meanplay = vec![Duration::ZERO;4];
    let mut meanverify = vec![Duration::ZERO;4];
    
    let mut pcsize = vec![0,0,0,0];
    let mut proofsize = vec![0,0,0,0];
    
    let mut meanpcsize = vec![0,0,0,0];
    let mut meanproofsize = vec![0,0,0,0];
  
    for _j in 0..iter{
    	
    	// Defines a random map
    	let maps = typesandproperties(csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
    	let t = maps.0; // vector of 5 elements
    	let p = maps.1; // vector of 14 elements
    	
        // Defines a random cell
        let cj = randomcell((&t).to_vec(),(&p).to_vec());
        let tj = cj.0;
        let pj = cj.1;
        
    	// Defines four different form of random clues 
        let clue0 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),0);
        let clue1 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),1);
        let clue2 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),2);
        let clue3 = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),3);
       
        let cluesplayers = vec![(&clue0).to_vec(),(&clue1).to_vec(),(&clue2).to_vec(),(&clue3).to_vec()];     
    
    	let answerplayer = vec![0,1];  
    
    	for i in 0..4{
    
    	    let startgen = Instant::now();
            let keyc = genclue(csprng, g0, (&cluesplayers[i]).to_vec()); 
	    let gentime = startgen.elapsed();
	    sumgenclue[i] += gentime; 
	    
	    let pc = keyc.0; 
    	    let sc = keyc.1;
    	    let _ = writepc((&pc).to_vec());
    	    let pcdata = fs::metadata("pc.txt");
    	    pcsize[i] += pcdata.expect("REASON").len();
    	    
    	    let startopenclue = Instant::now();
    	    openclue((&pc).to_vec(),sc);
    	    let opencluetime = startopenclue.elapsed();
    	    //assert!(open == (&cluesplayers[i]).to_vec(),"open != clue");
    	    //println!("open != clue: {:?}", open == (&cluesplayers[i]).to_vec());
    	    sumopenclue[i] += opencluetime;
    	    
    	    let mut answer: usize = 2;
    	    if i == 0 || i == 1{
    	    	answer = answerplayer[1];
    	    }
    	    if i == 2 || i == 3{
    	    	answer = answerplayer[0];
    	    }
    	    
    	    /*let mut badanswer: usize;
    	    if answer == 0{
        	badanswer = 1;
   	    }
    	    else{
    	        badanswer = 0;	
   	    }*/
    	
            let startplay = Instant::now();
            let proof = play(csprng,g0,(&pc).to_vec(),sc,tj,(&pj).to_vec(),answer);
            let playtime = startplay.elapsed();
            sumplay[i] += playtime;
            let _ = writeproof(&proof);
    	    let proofdata = fs::metadata("proof.txt");
    	    proofsize[i] += proofdata.expect("REASON").len();
        
            let startverify = Instant::now();
            verify(g0,proof,(&pc).to_vec(),tj,(&pj).to_vec(),answer);
            //assert!(b == true, "verify == false");
            //println!("verify == false: {:?}", b == true);
            let verifytime = startverify.elapsed(); 
            sumverify[i] += verifytime;  
        }        
    }  
    for i in 0..4{
    
    	meangen[i] = sumgenclue[i]/iter;
    	meanopen[i] = sumopenclue[i]/iter;
    	meanplay[i] = sumplay[i]/iter;
    	meanverify[i] = sumverify[i]/iter;
    	
    	meanpcsize[i] = pcsize[i]/u64::from(iter);
    	meanproofsize[i] = proofsize[i]/u64::from(iter);
    
    	println!("clue {:?} : mean of running time over {:?} iter for genclue {:?}, for openclue {:?}, for play {:?}, for verify {:?}",i+1,iter,meangen[i],meanopen[i],meanplay[i],meanverify[i]);
    	println!("clue {:?} : mean of size file over {:?} iter for pc {:?} bytes, for proof {:?} bytes",i+1,iter,meanpcsize[i],meanproofsize[i]);    
    } 
} 
  
// For measuring memory
pub fn writepc(pc: Vec<RistrettoPoint>) -> io::Result<()> {
    let mut file = File::create("pc.txt")?;
    file.write_fmt(format_args!("{:?}", pc))?;
    return Ok(())
}

pub fn writeproof(proof: &Proof) -> io::Result<()> {
    let mut file = File::create("proof.txt")?;
    file.write_fmt(format_args!("{:?}", proof))?;
    return Ok(())
}
  
// Scheme cc2
//csprng: random generator, g0: generator used to generates the key pk of the player, clue: vector of 3 RistrettoPoint which represent the clue = (C1,C2,C3), tj: type of the cell committed, pj: properties of the cell committed, answerplayer correspond to  bottom: correspond to a RistrettoPoint

pub fn schemecc2<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,clue: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,answer: usize){
              
    let startgenclue = Instant::now();
    let keyc = genclue(csprng,g0,(&clue).to_vec()); 
    let gentime = startgenclue.elapsed();
    println!("genclue took {:?}", gentime);
                       
    let pc = keyc.0; //pc = (pk, E1=(c11,c21), E2=(c12,c22), E3=(c13,c23) , Ei=Enc_pk(clue[i])
    let _ = writepc((&pc).to_vec());
    let sc = keyc.1; //sc = sk

    let startopenclue = Instant::now();
    openclue((&pc).to_vec(),sc);
    let opentime = startopenclue.elapsed();
    println!("openclue took {:?}", opentime);    
    //assert!(open == clue, "open != clue");
    //println!("open != clue: {:?}", open == clue);
	
    let startplay = Instant::now();
    let proof = play(csprng,g0,(&pc).to_vec(),sc,tj,(&pj).to_vec(),answer);
    let _ = writeproof(&proof);
    let playtime = startplay.elapsed();
    println!("play took {:?}",playtime);
	    
    let startverify = Instant::now();
    let b = verify(g0,proof,(&pc).to_vec(),tj,(&pj).to_vec(),answer);
    let vertime = startverify.elapsed(); 
    println!("verify took {:?}\n",vertime);
    //assert!(b == true,"verify == false");
    //println!("verify == false: {:?}", b == true);

    println!("answer: {:?}; verify: {:?}\n",answer,b); 	
}

// Functions for the protocol cc2

// Genclue: g is the generator used to generate the player public key
pub fn genclue <T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>,Scalar){

    let key = gen_elgamal(csprng,g0); // key.0 = g, key.1 = pk, key.2 = sk
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue{
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
        let c = dec_elgamal(sc,pc[k],pc[k+1]);
        clue.push(c); 
        k +=2;  
    } 
    return clue
}

// Answer
pub fn funanswer(clue: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>) -> usize{
    
    let bottom = RISTRETTO_BASEPOINT_POINT;
    if (clue[0] == tj || clue[1] == tj) && clue[2] == bottom{
        return 1
    }
    if clue[0] == bottom && clue[1] == bottom{
        for prop in pj{
            if clue[2] == prop{
                return 1
            }       
        }
    }
    return 0
}

// y0 is the public key pk of the player, y is the vector of "c2/tj" or "c2/p" s.t. Dec_sk((c1,c2)) = tj or p in pj, g0 is the generator used to generates the public key of the player, g is the vector of "c1" s.t. Dec_sk((c1,c2)) = tj or p in pj. x is the secret key sk of the player. (we prove also that the player use his correct secret key associated to the public key)

// prove play maybe 
fn prove_play_maybe<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values");
    	return  Proof::Error{err: false};
    }
    // Find the index w of the type or property of the cell committed s.t. c2/tj or c2/p equal to c1^sk
    let mut k = 0;
    while k < y.len() &&  y[k] != x * g[k]{
        k += 1;
    }
    let mut w = k;
    if w == y.len(){
        w -= 1;
    }
   
    // commit:
    let mut r = init_vec_ris(y.len()); // vector of commit r
    
    let rr = random_scalar(csprng); // picks a random scalar
    
    let r0 = rr * g0; 
    r[w] = rr * g[w];

    // simulation of proof for the yi such that yi =/= gi^x
    let mut c = init_vec_scal(y.len());  // ci is the challenge correspond to (yi,gi)
    let mut z = init_vec_scal(y.len());	 // zi is the respond correspond to (yi,gi)
    
    let respsim = simul_maybe(csprng,(&y).to_vec(), (&g).to_vec(), (&r).to_vec(), (&c).to_vec(), (&z).to_vec(), w);
    
    r = respsim.0; 
    c = respsim.1; 
    z = respsim.2;

    // build the challenge:  
    let mut conc: Vec<RistrettoPoint> = Vec::new();   //build the vector for concatenation and hash    
    conc.push(r0);
    for comm in &r{
        conc.push(*comm);
    }
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc); // cc is the general challenge = sum of all ci
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum = sum + chall;
    }
    c[w] = cc - sum; 
    //let c0 = cc; // c0 is the challenge correspond to (y0,g0) and equal to the general challenge cc
    
    // response:
    let z0 = rr + cc * x;
    z[w] = rr + c[w] * x;

    return Proof::ProofMaybe{r_0: r0, r_1: r, c_1: c, z_0: z0, z_1: z};
}

// simulator for the yi such that yi =/= gi^x 
fn simul_maybe<T: CryptoRng + RngCore>(csprng: &mut T,y: Vec<RistrettoPoint>,g: Vec<RistrettoPoint>,mut r: Vec<RistrettoPoint>,mut c: Vec<Scalar>,mut z: Vec<Scalar>,w: usize) -> (Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){
    
    for k in 0..y.len(){
        if k != w {
            let chall = random_scalar(csprng);
            c[k] = chall;
            let zz = random_scalar(csprng);
            z[k] = zz;
            r[k] = zz * g[k] - chall * y[k];   
        }
    }
    return(r,c,z)
}

fn verify_play_maybe(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, r0: RistrettoPoint, r: Vec<RistrettoPoint>, c: Vec<Scalar>, z0: Scalar, z: Vec<Scalar>) -> bool{
	
    // computes the hash from the given values
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc);
    let mut sum = convert_scalar([0u8;32]);
   
    for chall in &c{
        sum += chall;
    }
    
    // verify the computed hash is the sum of challenge and zi *gi = ri + cc * yi
    if cc == sum && z0 * g0 == r0 + cc * y0{
    	for i in 0..y.len(){
    	    if z[i] * g[i] != r[i] + c[i] * y[i]{
        	return false   
            }
        }
        return true;
    }
    else{
        return false      
    }    
}
	
fn prove_play_no<T: CryptoRng + RngCore>(csprng: &mut T,y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values");
    	return  Proof::Error{err: false};
    }

    let bb = random_scalar(csprng);
    let aa = x*bb;
	
    // commit 
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);
         
    let mut r: Vec<RistrettoPoint> = Vec::new(); 
    let r0 = rr * g0;
    for gg in &g{
        r.push(rr*gg);
    }
    
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-*yy);
    }
    
    let mut s: Vec<RistrettoPoint> = Vec::new(); 
    let s0 = ss*h0;
    for hh in &h{
        s.push(ss*hh);
    }
    
    let y0_p = aa * g0 + bb * h0;	// =1
    let mut y_p: Vec<RistrettoPoint> = Vec::new(); 

    for k in 0..g.len(){
	y_p.push(aa * g[k] + bb * h[k]);
    }
    
    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);   
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    let cc = hash_vec(conc);
    
    let uu = rr + cc * aa;
    let vv = ss + cc * bb;
    
    return Proof::ProofNo{y_0_p: y0_p, y_1_p: y_p, r_0: r0, r_r: r, s_0: s0, s_s: s, u_u: uu, v_v: vv}; 	   
}   
  
fn verify_play_no(y0: RistrettoPoint,y: Vec<RistrettoPoint>,g0: RistrettoPoint,g: Vec<RistrettoPoint>,h0: RistrettoPoint,h: Vec<RistrettoPoint>,y0_p: RistrettoPoint,y_p: Vec<RistrettoPoint>,r0: RistrettoPoint,r: Vec<RistrettoPoint>,s0: RistrettoPoint,s: Vec<RistrettoPoint>,uu: Scalar,vv: Scalar) -> bool{

    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    
    let cc = hash_vec(conc);
    
    if y0_p == RistrettoPoint::identity() && uu*g0 + vv*h0 == r0 + s0 + cc*y0_p{
    	for k in 0..y_p.len(){
            if y_p[k] == RistrettoPoint::identity(){ // we want y_p != id
                return false;
            }
            else{
                if uu*g[k] + vv*h[k] != r[k] + s[k] + cc*y_p[k]{
                    return false;
                }
            }
        }
    }
    else{
    	return false
    } 
    return true       
}

// g0 is the generator used to build the public key of player, pc is the public clue of the player, sc is the private clue of the player, (tj,pj) is the cell committed, answer is the response give by the payer for the cell (tj,pj)
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T,g0: RistrettoPoint,pc: Vec<RistrettoPoint>,sc: Scalar,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,answer: usize)-> Proof{

    let y0 = pc[0];

    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new();
     
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
	
    if answer == 1{ // maybe
        return prove_play_maybe(csprng, y0, y, g0, g, sc);  
    }
    if answer == 0{ // no
    	return prove_play_no(csprng, y0, y, g0, g, sc);
    }
    else{
	println!("Please give a correct answer");
	return Proof::Error{err: false};
    }	
}

pub fn verify(g0: RistrettoPoint,proof: Proof,pc: Vec<RistrettoPoint>,tj: RistrettoPoint,pj: Vec<RistrettoPoint>,answer: usize) -> bool{	
    
    let mut b = false;
    
    let y0 = pc[0];

    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new();
     
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
    
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-*yy);
    }
		
    match proof{
    	Proof::ProofMaybe{r_0, r_1, c_1, z_0, z_1} => { 
    	    if answer == 1{
    		b = verify_play_maybe(y0, y, g0, g, r_0, r_1, c_1, z_0, z_1); 
    	    }
    	},
    	Proof::ProofNo{y_0_p, y_1_p, r_0, r_r, s_0, s_s, u_u, v_v} => { 
    	    if answer == 0{
    		b = verify_play_no(y0, y, g0, g, h0, h, y_0_p, y_1_p, r_0, r_r, s_0 ,s_s, u_u, v_v);
    	    }
    	},
    	Proof::Error{err} => {   	
   	    if answer != 0 || answer != 1{
   		println!("Please give a correct answer");
   		b = err;
   	    }
    	},
    }
    return b  
}

